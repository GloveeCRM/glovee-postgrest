begin;

create schema if not exists comms;

create table if not exists comms.email (
    email_id bigserial primary key,
    from_email text not null,
    to_email text not null,
    subject text not null,
    html text not null,
    created_at timestamp with time zone default now()
);

create domain comms.email_status_type as text check (
    value in ('pending', 'sent', 'failed')
);

create table if not exists comms.email_status (
    status_id bigserial primary key,
    email_id bigint not null references comms.email(email_id) on delete cascade,
    status comms.email_status_type not null,
    attempts int not null default 0,
    created_at timestamp with time zone default now(),
    updated_at timestamp with time zone default now()
);

create schema if not exists queues;

create domain queues.task_type as text check (
    value in ('email')
);

create table if not exists queues.task (
    task_id bigserial primary key,
    task_type queues.task_type not null,
    resource_id bigint not null,
    priority int not null default 1 check (priority >= 1),
    retries int not null default 0,
    max_retries int not null default 3,
    created_at timestamp with time zone default now(),
    scheduled_at timestamp with time zone default now(),
    dequeued_at timestamp with time zone,
    completed_at timestamp with time zone,
    failed_at timestamp with time zone,
    error_message text,
    metadata jsonb
);

create or replace function comms.email_with_status(
    _email_id bigint
) returns jsonb
language plpgsql
security definer
as $$
declare
    _email jsonb;
begin
    select to_jsonb(e)
    into _email
    from comms.email e
    where e.email_id = _email_id;

    _email := _email || jsonb_build_object(
        'status', (
            select to_jsonb(es)
            from comms.email_status es
            where es.email_id = _email_id
        )
    );

    return _email;
end;
$$;

create or replace function queues.task_by_id(
    _task_id bigint
) returns queues.task
language sql
security definer
as $$
    select * from queues.task where task_id = _task_id;
$$;

create or replace function queues.enqueue_task(
    _task_type queues.task_type,
    _resource_id bigint,
    _priority int default 1,
    _metadata jsonb default '{}',
    _max_retries int default 3,
    _scheduled_at timestamp with time zone default now(),
    out created_task queues.task
) returns queues.task
language plpgsql
security definer
as $$
begin    
    insert into queues.task (
        task_type,
        resource_id,
        priority,
        metadata,
        max_retries,
        scheduled_at
    ) values (
        _task_type,
        _resource_id,
        _priority,
        _metadata,
        _max_retries,
        _scheduled_at
    ) returning * into created_task;

    return;
end;
$$;

create or replace function queues.dequeue_task(
    _task_type queues.task_type,
    out result jsonb
) returns jsonb
language plpgsql
security definer
as $$
declare
    _dequeued_task queues.task;
    _data jsonb;
begin
    select * into _dequeued_task
    from queues.task
    where task_type = _task_type
    and scheduled_at <= now()
    and dequeued_at is null
    and completed_at is null
    and failed_at is null
    and retries < max_retries
    order by priority desc, scheduled_at, task_id
    limit 1
    for update skip locked;

    if _dequeued_task.task_id is not null then
        update queues.task
        set dequeued_at = now()
        where task_id = _dequeued_task.task_id;

        _data := jsonb_build_object(
            _dequeued_task.task_type, 
            case _dequeued_task.task_type
                when 'email' then comms.email_with_status(_dequeued_task.resource_id)
            end
        );

        result := to_jsonb(_dequeued_task) || jsonb_build_object(
            'data', _data
        );
    else
        result := null;
    end if;

    return;
end;
$$;

create or replace function comms.update_email_status(
    _email_id bigint,
    _status comms.email_status_type,
    _increment_attempts boolean default false,
    out updated_email_status comms.email_status
) returns comms.email_status
language plpgsql
security definer
as $$
begin
    update comms.email_status
    set
        status = _status,
        attempts = case when _increment_attempts then attempts + 1 else attempts end,
        updated_at = now()
    where 
        email_id = _email_id
    returning * into updated_email_status;

    return;
end;
$$;

create or replace function queues.complete_task(
    _task_id bigint,
    out completed_task queues.task
) returns queues.task
language plpgsql
security definer
as $$
declare
    _task queues.task := queues.task_by_id(_task_id);
begin
    update queues.task
    set completed_at = now()
    where task_id = _task_id
    returning * into completed_task;

    case _task.task_type
        when 'email' then
            perform comms.update_email_status(
                _task.resource_id,
                'sent'
            );
    end case;

    return;
end;
$$;

create or replace function queues.fail_task(
    _task_id bigint,
    _error_message text default null,
    _metadata jsonb default '{}',
    out failed_task queues.task
) returns queues.task
language plpgsql
security definer
as $$
declare
    _task queues.task := queues.task_by_id(_task_id);
    _max_retries_reached boolean;
    _task_metadata jsonb;
begin
    -- check if max retries will be reached
    _max_retries_reached := _task.retries + 1 >= _task.max_retries;

    -- merge metadata if provided
    _task_metadata := coalesce(_metadata, '{}'::jsonb);
    if _task.metadata is not null and _task.metadata::text <> '{}'::text then
        _task_metadata := _task_metadata || _task.metadata;
    end if;

    -- If the final retry, update the resource status to failed
    if _max_retries_reached then
        case _task.task_type
            when 'email' then
                perform comms.update_email_status(
                    _task.resource_id,
                    'failed'
                );
        end case;
    end if;

    if _max_retries_reached then
        -- Final failure, mark task as failed
        update queues.task
        set 
            failed_at = now(),
            error_message = _error_message,
            metadata = _task_metadata,
            retries = _task.retries + 1
        where 
            task_id = _task_id
        returning * into failed_task;
    else
        -- Temporary failure - prepare for retry with exponential backoff
        update queues.task
        set 
            dequeued_at = null, -- Release the task so it can be picked up again
            error_message = _error_message,
            metadata = _task_metadata,
            retries = _task.retries + 1,
            scheduled_at = now() + (power(2, _task.retries) * interval '30 seconds')
        where 
            task_id = _task_id
        returning * into failed_task;
    end if;

    return;
end;
$$;

create or replace function queues.process_task_result(
    _task_id bigint,
    _success boolean,
    _error_message text default null,
    _metadata jsonb default '{}',
    out result jsonb
) returns jsonb
language plpgsql
security definer
as $$
declare
    _task queues.task := queues.task_by_id(_task_id);
begin
    if _task.task_id is null then
        result := jsonb_build_object(
            'success', false,
            'error', 'task_not_found'
        );
        return;
    end if;

    if _task.completed_at is not null or _task.failed_at is not null then
        result := jsonb_build_object(
            'success', false,
            'error', 'task_already_completed'
        );
        return;
    end if;

    if _success then
        perform queues.complete_task(_task_id);

        result := jsonb_build_object(
            'success', true,
            'message', 'task_completed',
            'task_type', _task.task_type,
            'resource_id', _task.resource_id
        );
    else
        perform queues.fail_task(_task_id, _error_message, _metadata);

        result := jsonb_build_object(
            'success', false,
            'message', 'task_failed',
            'task_type', _task.task_type,
            'resource_id', _task.resource_id,
            'retries', _task.retries,
            'max_retries', _task.max_retries,
            'error', _error_message
        );
    end if;

    return;
end;
$$;

-- Email enqueue trigger function
create or replace function queues.enqueue_email(
    _email_id bigint
)
returns void
language plpgsql
security definer
as $$
begin
    perform queues.enqueue_task(
        'email',
        _email_id,
        1,
        '{}'::jsonb,
        3,
        now()
    );
end;
$$;

create or replace function comms.validate_create_email_input(
    _from_email text,
    _to_email text,
    _subject text,
    _html text
) returns text
language plpgsql
security definer
as $$
begin
    if _from_email is null then
        return 'from_email_missing';
    end if;

    if _to_email is null then
        return 'to_email_missing';
    end if;

    if _subject is null then
        return 'subject_missing';
    end if;

    if _html is null then
        return 'html_missing';
    end if;

    return null;
end;
$$;

create or replace function comms.create_email(
    _from_email text,
    _to_email text,
    _subject text,
    _html text,
    out validation_failure_message text,
    out created_email comms.email
) returns record
language plpgsql
security definer
as $$
begin
    select comms.validate_create_email_input(
        _from_email,
        _to_email,
        _subject,
        _html
    ) into validation_failure_message;

    if validation_failure_message is not null then
        return;
    end if;

    insert into comms.email (
        from_email,
        to_email,
        subject,
        html
    ) values (
        _from_email,
        _to_email,
        _subject,
        _html
    ) returning * into created_email;

    insert into comms.email_status (
        email_id,
        status,
        attempts
    ) values (
        created_email.email_id,
        'pending',
        0
    );

    perform queues.enqueue_email(
        created_email.email_id
    );

    return;
end;
$$;

commit;