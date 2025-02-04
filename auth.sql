begin;

create table if not exists auth.password_reset_token (
    token_id bigint default utils.generate_random_id() not null primary key,
    token uuid not null default public.uuid_generate_v4(),
    user_id bigint not null references users.user (user_id),
    expires_at timestamp with time zone not null default (now() + '01:00:00'::interval),
    created_at timestamp with time zone not null default now()
);

create or replace function auth.validate_create_password_reset_token_input(
    _user_id bigint
)
returns text
language plpgsql security definer
as $$
begin
    if _user_id is null then
        return 'user_id_missing';
    end if;

    if not exists (
        select 1
        from users.user
        where user_id = _user_id
    ) then
        return 'user_not_found';
    end if;

    return null;
end;
$$;

create or replace function auth.create_password_reset_token(
    _user_id bigint,
    out validation_failure_message text,
    out created_token auth.password_reset_token
)
returns record
language plpgsql security definer
as $$
declare
    _expires_at timestamp with time zone;
begin
    raise exception '%', _user_id;
    validation_failure_message := auth.validate_create_password_reset_token_input(_user_id);
    if validation_failure_message is not null then
        return;
    end if;

    _expires_at := now() + '01:00:00'::interval;

    insert into auth.password_reset_token (user_id, expires_at)
    values (_user_id, _expires_at)
    returning * into created_token;

    return;
end;
$$;

create or replace function api.forgot_password(
    email text,
    org_name text
)
returns jsonb
language plpgsql security definer
as $$
declare
    _user_id bigint;
    _organization_id bigint := organizations.org_id_by_org_name($2);
    _create_password_reset_token_result record;
    _reset_password_email_result record;
begin
    select user_id
    from users.user u
    where u.email = $1
    and u.organization_id = _organization_id
    into _user_id;

    if _user_id is null then
        raise exception 'Forgot Password Failed'
            using
                detail = 'Invalid Request Payload',
                hint = 'user_not_found';
    end if;

    _create_password_reset_token_result := auth.create_password_reset_token(_user_id);
    
    if _create_password_reset_token_result.validation_failure_message is not null then
        raise exception 'Forgot Password Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_password_reset_token_result.validation_failure_message;
    end if;

    _reset_password_email_result := comms.send_email(
        'password@glovee.io',
        email,
        'Reset your password',
        'You can reset your password by clicking the following link: ' || 'https://' || org_name || '.glovee.io/set-new-password?resetPasswordToken=' || (_create_password_reset_token_result.created_token).token,
        _organization_id
    );

    if _reset_password_email_result.failure_message is not null then
        raise exception 'Forgot Password Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _reset_password_email_result.failure_message;
    end if;

    return jsonb_build_object(
        'message', 'Password reset email sent'
    );
end;
$$;

grant execute on function api.forgot_password(text, text) to anon;

create or replace function auth.reset_password_token_by_token(
    _token uuid
)
returns auth.password_reset_token
    language sql
    security definer
as $$
    select *
    from auth.password_reset_token
    where token = _token
    and expires_at > now()
$$;

create or replace function users.validate_update_user_password_input(
    _organization_id bigint,
    _user_id bigint,
    _new_password text
)
returns text
language plpgsql security definer
as $$
begin
    if _user_id is null then
        return 'user_not_found';
    end if;

    if _new_password is null then
        return 'new_password_missing';
    end if;

    if _organization_id is null then
        return 'organization_not_found';
    end if;

    if length(_new_password) < 8 then
        return 'password_too_short';
    end if;
    if not (_new_password ~ '[A-Z]') then
        return 'password_missing_uppercase';
    end if;
    if not (_new_password ~ '[a-z]') then
        return 'password_missing_lowercase';
    end if;
    if not (_new_password ~ '[0-9]') then
        return 'password_missing_number';
    end if;
    if not (_new_password ~ '[!@#$%^&*(),.?":{}|<>]') then
        return 'password_missing_special_character';
    end if;

    if not exists (
        select 1
        from users.user
        where user_id = _user_id
        and organization_id = _organization_id
    ) then
        return 'user_not_found';
    end if;

    return null;
end;
$$;

create or replace function users.update_user_password(
    _organization_id bigint,
    _user_id bigint,
    _new_password text,
    out validation_failure_message text,
    out updated_user users.user
)
    returns record
    language plpgsql
    security definer
as $$
declare
    _hashed_password text;
begin
    validation_failure_message := users.validate_update_user_password_input(_organization_id, _user_id, _new_password);
    if validation_failure_message is not null then
        return;
    end if;

    _hashed_password := crypt(_new_password, gen_salt('bf'));

    update users.user
    set hashed_password = _hashed_password
    where user_id = _user_id
    and organization_id = _organization_id
    returning * into updated_user;

    return;
end;
$$;

create or replace function api.set_new_password(
    org_name text,
    reset_password_token uuid,
    new_password text
)
returns jsonb
language plpgsql security definer
as $$
declare
    _organization_id bigint := organizations.org_id_by_org_name(org_name);
    _reset_password_token auth.password_reset_token := auth.reset_password_token_by_token(reset_password_token);
    _update_user_password_result record;
    _reset_password_success_email_result record;
begin
    if _reset_password_token is null then
        raise exception 'Set New Password Failed'
            using
                detail = 'Invalid Request Payload',
                hint = 'reset_password_token_not_found';
    end if;

    _update_user_password_result := users.update_user_password(
        _organization_id,
        _reset_password_token.user_id,
        new_password
    );

    if _update_user_password_result.validation_failure_message is not null then
        raise exception 'Set New Password Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _update_user_password_result.validation_failure_message;
    end if;

    delete from auth.password_reset_token
    where token = reset_password_token;

    _reset_password_success_email_result := comms.send_email(
        'password@glovee.io',
        (_update_user_password_result.updated_user).email,
        'Password reset successful',
        'Your password has been reset successfully',
        _organization_id
    );

    if _reset_password_success_email_result.failure_message is not null then
        raise exception 'Set New Password Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _reset_password_success_email_result.failure_message;
    end if;

    return jsonb_build_object(
        'message', 'password_reset_success'
    );
end;
$$;

grant execute on function api.set_new_password(text, uuid, text) to anon;

commit;
