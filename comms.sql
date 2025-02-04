begin;

create schema if not exists comms;

create table if not exists comms.email (
    email_id bigint default utils.generate_random_id() not null primary key,
    from_email text not null,
    to_email text not null,
    subject text not null,
    html text not null,
    created_at timestamp with time zone default now()
);

create or replace function comms.send_email(
    _from_email text,
    _to_email text,
    _subject text,
    _html text,
    _organization_id bigint default null,
    out failure_message text,
    out generated_email comms.email
)
returns record
language plpgsql
security definer
as $$
declare
    _email_payload jsonb;
    _email_response record;
    _current_org_id bigint;
    _organization_config organizations.organization_config;
begin
    if _organization_id is null then
        _current_org_id := auth.current_user_organization_id();
    else
        _current_org_id := _organization_id;
    end if;

    _organization_config := organizations.config_by_org_id(_current_org_id);

    _email_payload := json_build_object(
        'from', _from_email,
        'to', _to_email,
        'subject', _subject,
        'html', _html
    );

    _email_response := aws.generate_comms(
        'email',
        _email_payload,
        _organization_config.aws_region
    );

    if _email_response.failure_message is not null then
        failure_message := _email_response.failure_message;
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
    ) returning * into generated_email;

    return;
end;
$$;

commit;