begin;

create or replace function forms.form_content(
    _form_id bigint,
    _include_form_categories boolean default false,
    _include_form_sections boolean default false,
    _include_completion_rates boolean default false,
    out form jsonb,
    out form_categories jsonb,
    out form_sections jsonb,
    out validation_failure_message text
)
returns record
language plpgsql security definer
as $$
begin
    select to_jsonb(f) ||
           case
               when _include_completion_rates then
                   jsonb_build_object('completion_rate', forms.form_completion_rate(_form_id)
                   )
               else '{}'::jsonb
           end
    into form
    from forms.form f
    where f.form_id = _form_id;

    if form is null then
        validation_failure_message := 'form_not_found';
        return;
    end if;

    if _include_form_categories then
        select jsonb_agg(
            to_jsonb(fc) ||
            case
                when _include_completion_rates then
                    jsonb_build_object('completion_rate', forms.form_category_completion_rate(fc.form_category_id))
                else '{}'::jsonb
            end
            order by fc.category_position, fc.form_category_id
        )
        into form_categories
        from forms.form_category fc
        where fc.form_id = _form_id;
    end if;

    if _include_form_sections then
        select jsonb_agg(to_jsonb(fs) ||
            case
                when _include_completion_rates then
                    jsonb_build_object('completion_rate', forms.form_section_completion_rate(fs.form_section_id))
                else '{}'::jsonb
            end
            order by fc.category_position, fs.section_position, fs.form_section_id
        )
        into form_sections
        from forms.form_section fs
        join forms.form_category fc
        using (form_category_id)
        where fc.form_id = _form_id;
    end if;

    return;
end;
$$;

create or replace function forms.form_owner_id(_form_id bigint)
returns bigint
language sql
security definer
as $$
    select coalesce(
        (
            select ft.created_by 
            from forms.form_template ft 
            where ft.form_id = _form_id
        ),
        (
            select a.user_id
            from applications.application a 
            join applications.application_form af
            using (application_id)
            where af.form_id = _form_id
        )
    )
    from forms.form f
    where f.form_id = _form_id;
$$;

create or replace function api.form_content(
    form_id bigint,
    include_form_categories boolean default false,
    include_form_sections boolean default false,
    include_completion_rates boolean default false
)
returns jsonb
language plpgsql security definer
as $$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _current_user_id bigint := auth.current_user_id();
    _current_user_organization_id bigint := auth.current_user_organization_id();
    _form_owner_id bigint := forms.form_owner_id(form_id);
    _form_content record;
    _form_organization_id bigint := forms.form_organization_id(form_id);
begin
    if (_form_organization_id != _current_user_organization_id)
    or (_current_user_role = 'org_client' and _form_owner_id != _current_user_id)
    or _current_user_role not in ('org_admin', 'org_owner', 'org_client') then
        raise exception 'Form Retrieval Failed'
            using
                detail = 'You are not authorized to retrieve the form',
                hint = 'unauthorized';
    end if;

    select *
    into _form_content
    from forms.form_content(
        form_id,
        include_form_categories,
        include_form_sections,
        include_completion_rates
    );

    if _form_content.validation_failure_message is not null then
        raise exception 'Form Retrieval Failed'
            using
                detail = 'Validation Failed',
                hint = _form_content.validation_failure_message;
    end if;

    return jsonb_build_object(
        'form', _form_content.form,
        'form_categories', _form_content.form_categories,
        'form_sections', _form_content.form_sections
    );
end;
$$;

grant execute on function api.form_content(bigint, boolean, boolean, boolean) to authenticated;

create or replace function api.application_form(
    application_form_id bigint
)
returns jsonb
language plpgsql
security definer
as $$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _application_form_owner_id bigint := applications.application_form_owner_id(application_form_id);
    _application_form applications.application_form;
begin
    if (_current_user_role = 'org_client' and _application_form_owner_id != auth.current_user_id())
    or _current_user_role not in ('org_admin', 'org_owner', 'org_client') then
        raise exception 'Application Form Retrieval Failed'
            using
                detail = 'You are not authorized to retrieve the application form',
                hint = 'unauthorized';
    end if;

    select af.*
    into _application_form
    from applications.application_form af
    where af.application_form_id = $1
    and af.organization_id = auth.current_user_organization_id();

    if _application_form is null then
        raise exception 'Application Form Retrieval Failed'
            using
                detail = 'Application form not found',
                hint = 'application_form_not_found';
    end if;

    return jsonb_build_object(
        'application_form', to_jsonb(_application_form)
    );
end;
$$;

grant execute on function api.application_form(bigint) to authenticated;

create or replace function forms.form_section_form_id(_form_section_id bigint) returns bigint
    language sql
    stable
as
$$
    select f.form_id
    from forms.form f
    join forms.form_category fc
    using (form_id)
    join forms.form_section fs
    using (form_category_id)
    where fs.form_section_id = _form_section_id;
$$;

create or replace function forms.form_section_question_sets(_form_section_id bigint) returns forms.form_question_set[]
    language sql
    stable
as
$$
    select array_agg(fqs order by fc.category_position, fs.section_position, fqs.form_question_set_position)
    from forms.form_question_set fqs
    join forms.form_section fs 
    using (form_section_id)
    join forms.form_category fc
    using (form_category_id)
    where fqs.form_section_id = _form_section_id;
$$;

create or replace function forms.form_section_questions(_form_section_id bigint, _include_answers boolean default false) returns jsonb
    language plpgsql
    stable
as
$$
declare
    _form_section_questions jsonb;
begin
    select jsonb_agg(
        to_jsonb(fq) || jsonb_build_object(
            'form_question_settings', to_jsonb(forms.form_question_settings(fq.form_question_id)),
            'form_question_options', (
                select jsonb_agg(to_jsonb(options))
                from forms.form_question_options(fq.form_question_id) as options
            ),
            'form_question_default_options', to_jsonb(forms.form_question_default_options(fq.form_question_id))
        ) || case 
            when _include_answers then jsonb_build_object(
                'answer', forms.form_question_answer(fq.form_question_id)
            )
            else '{}'::jsonb
        end
        order by fc.category_position, fs.section_position, fqs.form_question_set_position, fq.form_question_position
    ) into _form_section_questions
    from forms.form_question fq
    join forms.form_question_set fqs
    using (form_question_set_id)
    join forms.form_section fs
    using (form_section_id)
    join forms.form_category fc
    using (form_category_id)
    where fqs.form_section_id = _form_section_id;

    return coalesce(_form_section_questions, '[]'::jsonb);
end;
$$;

create or replace function api.form_section_question_sets_and_questions(form_section_id bigint, include_answers boolean default false) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _form_id bigint := forms.form_section_form_id(form_section_id);
    _form_owner_id bigint := forms.form_owner_id(_form_id);
begin
    if (_current_user_role = 'org_client' and _form_owner_id != auth.current_user_id())
    or _current_user_role not in ('org_admin', 'org_owner', 'org_client') then
        raise exception 'Form Section Question Sets And Questions Retrieval Failed'
            using
                detail = 'You are not authorized to retrieve the form section question sets and questions',
                hint = 'unauthorized';
    end if;

    return jsonb_build_object(
        'form_question_sets', to_jsonb(forms.form_section_question_sets(form_section_id)),
        'form_questions', forms.form_section_questions(form_section_id, include_answers)
    );
end;
$$;

grant execute on function api.form_section_question_sets_and_questions(bigint, boolean) to authenticated;

create or replace function forms.validate_update_form_input(
    _form_id bigint,
    _form_name text
) returns text
    language plpgsql
    security definer
as
$$
begin
    if _form_id is null or _form_id <= 0 then
        return 'missing_form_id';
    end if;

    if _form_name is null or _form_name = '' then
        return 'missing_form_name';
    end if;

    if not exists (
        select 
            1
        from 
            forms.form f
        where 
            f.form_id = _form_id
    ) then
        return 'form_not_found';
    end if;

    return null;
end;
$$;

create or replace function forms.update_form(
    _form_id bigint,
    _form_name text,
    _form_description text default null,
    out validation_failure_message text,
    out updated_form jsonb
) returns record
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := forms.validate_update_form_input(_form_id, _form_name);
    if validation_failure_message is not null then
        return;
    end if;

    update 
        forms.form
    set 
        form_name = _form_name,
        form_description = _form_description
    where 
        form_id = _form_id;

    select
        to_jsonb(f)
    into 
        updated_form
    from
        forms.form f
    where
        f.form_id = _form_id;

    return;
end;
$$;

create or replace function api.update_form(form_id bigint, form_name text, form_description text default null) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_id bigint := auth.current_user_id();
    _current_user_role users.user_role := auth.current_user_role();
    _current_user_organization_id bigint := auth.current_user_organization_id();
    _form_organization_id bigint := forms.form_organization_id(form_id);
    _form_owner_id bigint := forms.form_owner_id(form_id);
    _update_form_result record;
begin
    if (_form_organization_id != _current_user_organization_id)
    or (_current_user_role = 'org_client' and _form_owner_id != _current_user_id)
    or _current_user_role not in ('org_admin', 'org_owner', 'org_client') then
        raise exception 'Form Update Failed'
            using
                detail = 'You are not authorized to update this form',
                hint = 'unauthorized';
    end if;

    _update_form_result := forms.update_form(form_id, form_name, form_description);
    if _update_form_result.validation_failure_message is not null then
        raise exception 'Form Update Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _update_form_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'form', _update_form_result.updated_form
    );
end;
$$;

grant execute on function api.update_form(bigint, text, text) to authenticated;

create or replace function forms.form_question_form_category_id(_form_question_id bigint) returns bigint
    language sql
    stable
as
$$
    select
        fc.form_category_id
    from
        forms.form_category fc
    join
        forms.form_section fs
    using
        (form_category_id)
    join
        forms.form_question_set
    using
        (form_section_id)
    join
        forms.form_question fq
    using
        (form_question_set_id)
    where
        fq.form_question_id = _form_question_id;
$$;

create or replace function forms.form_question_form_section_id(_form_question_id bigint) returns bigint
    language sql
    stable
as
$$
    select
        fs.form_section_id
    from
        forms.form_section fs
    join
        forms.form_category fc
    using
        (form_category_id)
    join
        forms.form_question_set
    using
        (form_section_id)
    join
        forms.form_question fq
    using
        (form_question_set_id)
    where
        fq.form_question_id = _form_question_id;
$$;

create or replace function api.upsert_form_answer(
    form_question_id bigint,
    answer_text text default null,
    answer_date date default null,
    answer_files jsonb default null,
    answer_options jsonb default null
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _current_user_org_id bigint := auth.current_user_organization_id();
    _current_user_id bigint := auth.current_user_id();
    _user_org_config organizations.organization_config;
    _upsert_form_answer_result record;
    _create_file_result record;
    _create_form_answer_file_result record;
    _create_form_answer_option_result record;
    _answer_file jsonb;
    _answer_option jsonb;
    _existing_file_ids bigint[];
    _input_file_ids bigint[];
    _file_ids_to_delete bigint[];
    _existing_option_ids bigint[];
    _input_option_ids bigint[];
    _option_ids_to_delete bigint[];
    _updated_form_answer jsonb;
    _form_question_form_category_id bigint := forms.form_question_form_category_id(form_question_id);
    _form_question_form_section_id bigint := forms.form_question_form_section_id(form_question_id);
    _completion_rates jsonb;
begin
    if _current_user_role != 'org_client' then
        raise exception 'Form Answer Upsert Failed'
            using
                detail = 'You are not authorized to upsert form answers',
                hint = 'unauthorized';
    end if;

    _upsert_form_answer_result := forms.upsert_form_answer(
        form_question_id,
        answer_text,
        answer_date
    );
    if _upsert_form_answer_result.validation_failure_message is not null then
        raise exception 'Form Answer Upsert Failed'
            using
                detail = 'Validation failed',
                hint = _upsert_form_answer_result.validation_failure_message;
    end if;

    -- Handle files
    select array_agg(file_id)
    into _existing_file_ids
    from forms.form_answer_file
    where form_answer_id = (_upsert_form_answer_result.upserted_form_answer).form_answer_id;

    select array_agg((answer_file->'file'->>'file_id')::bigint)
    into _input_file_ids
    from jsonb_array_elements(answer_files) as answer_file
    where answer_file->'file'->>'file_id' is not null;

    _existing_file_ids := coalesce(_existing_file_ids, array[]::bigint[]);
    _input_file_ids := coalesce(_input_file_ids, array[]::bigint[]);

    select array_agg(file_id)
    into _file_ids_to_delete
    from (
        select unnest(_existing_file_ids) as file_id
        except
        select unnest(_input_file_ids)
    ) as files_to_remove;

    if _file_ids_to_delete is not null then
        delete from files.file f
        where f.file_id = any(_file_ids_to_delete);
    end if;

    if answer_files is not null and jsonb_array_length(answer_files) > 0 then
        _user_org_config := organizations.config_by_org_id(_current_user_org_id);

        for _answer_file in select * from jsonb_array_elements(answer_files)
        loop
            if (_answer_file->'file'->>'file_id') is null then
                _create_file_result := files.create_file(
                    (_answer_file->'file'->>'object_key')::text,
                    (_answer_file->'file'->>'name')::text,
                    _user_org_config.s3_bucket,
                    _user_org_config.s3_region,
                    (_answer_file->'file'->>'mime_type')::text,
                    (_answer_file->'file'->>'size')::bigint,
                    _current_user_org_id,
                    _current_user_id,
                    (_answer_file->'file'->'metadata')::jsonb
                );
                if _create_file_result.validation_failure_message is not null then
                    raise exception 'Form Answer File Creation Failed'
                        using
                            detail = 'Validation failed',
                            hint = _create_file_result.validation_failure_message;
                end if;

                _create_form_answer_file_result := forms.create_form_answer_file(
                    (_upsert_form_answer_result.upserted_form_answer).form_answer_id,
                    (_create_file_result.created_file).file_id
                );
                if _create_form_answer_file_result.validation_failure_message is not null then
                    raise exception 'Form Answer File Association Failed'
                        using
                            detail = 'Validation failed',
                            hint = _create_form_answer_file_result.validation_failure_message;
                end if;
            end if;
        end loop;
    end if;

    -- Handle options
    select array_agg(form_question_option_id)
    into _existing_option_ids
    from forms.form_answer_option
    where form_answer_id = (_upsert_form_answer_result.upserted_form_answer).form_answer_id;

    select array_agg((answer_option->>'form_question_option_id')::bigint)
    into _input_option_ids
    from jsonb_array_elements(answer_options) as answer_option
    where answer_option->>'form_question_option_id' is not null;

    _existing_option_ids := coalesce(_existing_option_ids, array[]::bigint[]);
    _input_option_ids := coalesce(_input_option_ids, array[]::bigint[]);

    select array_agg(option_id)
    into _option_ids_to_delete
    from (
        select unnest(_existing_option_ids) as option_id
        except
        select unnest(_input_option_ids)
    ) as options_to_remove;

    if _option_ids_to_delete is not null then
        delete from forms.form_answer_option
        where form_answer_id = (_upsert_form_answer_result.upserted_form_answer).form_answer_id
        and form_question_option_id = any(_option_ids_to_delete);
    end if;

    if answer_options is not null and jsonb_array_length(answer_options) > 0 then
        for _answer_option in select * from jsonb_array_elements(answer_options)
        loop
            if not (_answer_option->>'form_question_option_id')::bigint = any(_existing_option_ids) then
                _create_form_answer_option_result := forms.create_form_answer_option(
                    (_upsert_form_answer_result.upserted_form_answer).form_answer_id,
                    (_answer_option->>'form_question_option_id')::bigint
                );
                if _create_form_answer_option_result.validation_failure_message is not null then
                    raise exception 'Form Answer Option Creation Failed'
                        using
                            detail = 'Validation failed',
                            hint = _create_form_answer_option_result.validation_failure_message;
                end if;
            end if;
        end loop;
    end if;

    _updated_form_answer := forms.form_question_answer(form_question_id);
    _completion_rates := jsonb_build_object(
        'form_category', jsonb_build_object(
            'form_category_id', _form_question_form_category_id,
            'completion_rate', forms.form_category_completion_rate(_form_question_form_category_id)
        ),
        'form_section', jsonb_build_object(
            'form_section_id', _form_question_form_section_id,
            'completion_rate', forms.form_section_completion_rate(_form_question_form_section_id)
        )
    );

    return jsonb_build_object(
        'form_answer', _updated_form_answer,
        'completion_rates', _completion_rates
    );
end;
$$;

grant execute on function api.upsert_form_answer(bigint, text, date, jsonb, jsonb) to authenticated;

create or replace function forms.form_question_set_category_id(_form_question_set_id bigint) returns bigint
    language sql
    stable
as
$$
    select
        fc.form_category_id
    from
        forms.form_category fc
    join
        forms.form_section fs
    using
        (form_category_id)
    join
        forms.form_question_set fqs
    using
        (form_section_id)
    where
        fqs.form_question_set_id = _form_question_set_id;
$$;

create or replace function forms.form_question_set_section_id(_form_question_set_id bigint) returns bigint
    language sql
    stable
as
$$
    select
        fs.form_section_id
    from
        forms.form_section fs
    join
        forms.form_category fc
    using
        (form_category_id)
    join
        forms.form_question_set fqs
    using
        (form_section_id)
    where
        fqs.form_question_set_id = _form_question_set_id;
$$;

create or replace function api.repeat_application_form_question_set(form_question_set_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _form_question_set forms.form_question_set;
    _new_form_question_set_position int;
    _form_question_set_category_id bigint := forms.form_question_set_category_id(form_question_set_id);
    _form_question_set_section_id bigint := forms.form_question_set_section_id(form_question_set_id);
    _completion_rates jsonb;
begin
    select *
    into _form_question_set
    from forms.form_question_set fqs
    where fqs.form_question_set_id = $1;

    if _form_question_set is null then
        raise exception 'Form Template Question Set Duplication Failed'
            using
                detail = 'The form template question set was not found',
                hint = 'form_question_set_not_found';
    end if;

    select coalesce(max(form_question_set_position), 0) + 1
    into _new_form_question_set_position
    from forms.form_question_set
    where parent_form_question_set_id = _form_question_set.parent_form_question_set_id;

    _form_question_set.form_question_set_position := _new_form_question_set_position;

    perform forms.duplicate_form_question_set(
        _form_question_set,
        _form_question_set.form_section_id,
        _form_question_set.parent_form_question_set_id,
        null
    );

    _completion_rates := jsonb_build_object(
        'form_category', jsonb_build_object(
            'form_category_id', _form_question_set_category_id,
            'completion_rate', forms.form_category_completion_rate(_form_question_set_category_id)
        ),
        'form_section', jsonb_build_object(
            'form_section_id', _form_question_set_section_id,
            'completion_rate', forms.form_section_completion_rate(_form_question_set_section_id)
        )
    );

    return jsonb_build_object(
        'form_question_sets', to_jsonb(forms.form_section_question_sets(_form_question_set.form_section_id)),
        'form_questions', forms.form_section_questions(_form_question_set.form_section_id, true),
        'completion_rates', _completion_rates
    );
end;
$$;

grant execute on function api.repeat_application_form_question_set(bigint) to authenticated;

create or replace function api.delete_application_form_question_set(
    form_question_set_id bigint
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _target_form_section_id bigint := forms.form_section_id_by_form_question_set_id(form_question_set_id);
    _validation_failure_message text;
    _form_question_set_category_id bigint := forms.form_question_set_category_id(form_question_set_id);
    _form_question_set_section_id bigint := forms.form_question_set_section_id(form_question_set_id);
    _completion_rates jsonb;
begin
    _validation_failure_message := forms.delete_form_question_set(form_question_set_id);
    if _validation_failure_message is not null then
        raise exception 'Application Form Question Set Deletion Failed'
            using
                detail = 'Application Form Question Set not found',
                hint = 'form_question_set_not_found';
    end if;

    _completion_rates := jsonb_build_object(
        'form_category', jsonb_build_object(
            'form_category_id', _form_question_set_category_id,
            'completion_rate', forms.form_category_completion_rate(_form_question_set_category_id)
        ),
        'form_section', jsonb_build_object(
            'form_section_id', _form_question_set_section_id,
            'completion_rate', forms.form_section_completion_rate(_form_question_set_section_id)
        )
    );

    return jsonb_build_object(
        'form_question_sets', to_jsonb(forms.form_section_question_sets(_target_form_section_id)),
        'form_questions', forms.form_section_questions(_target_form_section_id, true),
        'completion_rates', _completion_rates
    );
end;
$$;

grant execute on function api.delete_application_form_question_set(bigint) to authenticated;

commit;