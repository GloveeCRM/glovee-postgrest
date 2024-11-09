rollback;

begin;

-- Drop existing schemas if they exist (to ensure clean setup)
drop schema if exists public cascade;
drop schema if exists api cascade;
drop schema if exists config cascade;
drop schema if exists users cascade;
drop schema if exists organizations cascade;
drop schema if exists auth cascade;
drop schema if exists files cascade;
drop schema if exists utils cascade;
drop schema if exists aws cascade;

-- Create schemas
create schema public;
create schema api;
create schema config;
create schema users;
create schema organizations;
create schema auth;
create schema files;
create schema utils;
create schema aws;

-- Roles
do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'anon') then
        create role anon nologin;
    end if;
    if not exists (select 1 from pg_roles where rolname = 'authenticated') then
        create role authenticated nologin;
    end if;
end
$$;

-- Grant permissions
grant usage on schema 
    api,
    users,
    auth,
    aws
to anon, authenticated;

alter default privileges revoke execute on functions from public;

-- Utilities
create extension if not exists pgcrypto;
create extension if not exists aws_commons;
create extension if not exists aws_lambda;

create or replace function utils.generate_random_id() returns bigint
    language plpgsql
as
$$
declare
    _base_id bigint;
begin
    _base_id := (extract(epoch from now())::bigint % 1000000000) * 100000 + (random() * 99999)::int;
    return _base_id;
end;
$$;

-- Drop existing dependencies first to avoid conflicts
drop view if exists api.organizations;
drop table if exists config.config cascade;
drop table if exists files.file cascade;
drop table if exists organizations.organization_config cascade;
drop table if exists users.user cascade;
drop table if exists organizations.organization cascade;
drop type if exists users.user_role;
drop type if exists users.user_status;

-- Domains
create domain users.user_role as text
check (
    value in ('org_client', 'org_admin', 'org_owner', 'g_admin', 'g_owner')
);

create domain users.user_status as text
check (
    value in ('active', 'inactive')
);

-- Tables
create table config.config
(
    key text not null primary key,
    value text not null
);

create table organizations.organization
(
    organization_id bigint default utils.generate_random_id() not null primary key,
    name text,
    org_name text not null unique,
    logo_file_id bigint,
    created_at timestamp with time zone default now(),
    updated_at timestamp with time zone default now()
);

create table users.user
(
    user_id bigint default utils.generate_random_id() not null primary key,
    organization_id bigint references organizations.organization(organization_id) on delete cascade,
    email text not null,
    hashed_password text,
    first_name text,
    last_name text,
    profile_picture_file_id bigint,
    created_at timestamp with time zone default now(),
    updated_at timestamp with time zone default now(),
    constraint unique_email_organization unique (email, organization_id)
);

create table users.account_status
(
    account_status_id bigint default utils.generate_random_id() not null primary key,
    user_id bigint references users.user(user_id) on delete cascade,
    status users.user_status not null,
    created_at timestamp with time zone default now()
);

create table users.account_role
(
    account_role_id bigint default utils.generate_random_id() not null primary key,
    user_id bigint references users.user(user_id) on delete cascade,
    role users.user_role not null,
    created_at timestamp with time zone default now()
);

create table organizations.organization_config
(
    organization_id bigint references organizations.organization(organization_id) on delete cascade,
    s3_bucket text not null,
    s3_region text not null,
    created_at timestamp with time zone default now(),
    updated_at timestamp with time zone default now(),
    created_by bigint references users.user(user_id) on delete set null,
    updated_by bigint references users.user(user_id) on delete set null,
    constraint unique_org_config unique (organization_id)
);

create table files.file
(
    file_id bigint default utils.generate_random_id() not null primary key,
    name text,
    object_key text not null,
    bucket text not null,
    region text not null,
    mime_type text not null,
    size bigint not null,
    version bigint not null default 1 check (version > 0),
    is_public boolean not null default false,
    metadata jsonb,
    created_at timestamp with time zone default now(),
    updated_at timestamp with time zone default now(),
    created_by bigint references users.user(user_id) on delete set null,
    updated_by bigint references users.user(user_id) on delete set null,
    organization_id bigint references organizations.organization(organization_id) on delete set null,
    constraint unique_object_key_version_org unique (object_key, version, organization_id)
);

-- Add foreign key constraints
alter table organizations.organization
    add constraint logo_file_id_fk
    foreign key (logo_file_id)
    references files.file(file_id)
    on delete set null;

alter table users.user
    add constraint profile_picture_file_id_fk
    foreign key (profile_picture_file_id)
    references files.file(file_id)
    on delete set null;

-- Functions
-- Config
create or replace function config.get(_key text) returns text
    language plpgsql
    stable
as
$$
declare
    _config_value text;
begin
    select value into _config_value
    from config.config
    where config.config.key = _key;

    return _config_value;
end;
$$;

create or replace function config.item_from_app_settings(_key text) returns text
    language sql
as
$$
    select current_setting('app.settings.' || _key);
$$;

-- Auth
create function auth.url_encode(data bytea) returns text
    immutable
    language sql
as
$$
    select translate(encode(data, 'base64'), E'+/=\n', '-_');
$$;

create function auth.algorithm_sign(signables text, secret text, algorithm text) returns text
    immutable
    language sql
as
$$
with
  alg as (
    select case
      when algorithm = 'HS256' then 'sha256'
      when algorithm = 'HS384' then 'sha384'
      when algorithm = 'HS512' then 'sha512'
      else '' end as id
  )  -- hmac throws error
  select
    auth.url_encode(hmac(signables, secret, alg.id))
  from
    alg;
$$;

create function auth.url_decode(data text) returns bytea
    immutable
    language sql
as
$$
with t as (select translate(data, '-_', '+/') as trans),
     rem as (select length(t.trans) % 4 as remainder from t) -- compute padding size
    select decode(
        t.trans ||
        case when rem.remainder > 0
           then repeat('=', (4 - rem.remainder))
           else '' end,
    'base64') from t, rem;
$$;

create function auth.sign(payload jsonb, secret text, algorithm text DEFAULT 'HS256'::text) returns text
    immutable
    language sql
as
$$
with
  header as (
    select auth.url_encode(convert_to('{"alg":"' || algorithm || '","typ":"JWT"}', 'utf8')) as data
    ),
  payload as (
    select auth.url_encode(convert_to(payload::text, 'utf8')) as data
    ),
  signables as (
    select header.data || '.' || payload.data as data from header, payload
    )
select
    signables.data || '.' ||
    auth.algorithm_sign(signables.data, secret, algorithm) from signables;
$$;

create function auth.try_cast_double(inp text) returns double precision
    immutable
    language plpgsql
as
$$
  begin
    begin
      return inp::double precision;
    exception
      when others then return null;
    end;
  end;
$$;

create function auth.verify(token text, secret text, algorithm text DEFAULT 'HS256'::text)
    returns TABLE(header jsonb, payload jsonb, valid boolean)
    immutable
    language sql
as
$$
  select
    jwt.header as header,
    jwt.payload as payload,
    jwt.signature_ok and tstzrange(
      to_timestamp(auth.try_cast_double(jwt.payload->>'nbf')),
      to_timestamp(auth.try_cast_double(jwt.payload->>'exp'))
    ) @> current_timestamp as valid
  from (
    select
      convert_from(auth.url_decode(r[1]), 'utf8')::jsonb as header,
      convert_from(auth.url_decode(r[2]), 'utf8')::jsonb as payload,
      r[3] = auth.algorithm_sign(r[1] || '.' || r[2], secret, algorithm) as signature_ok
    from regexp_split_to_array(token, '\.') r
  ) jwt
$$;

create or replace function auth.current_user_organization_id()
returns bigint
language sql
security definer
as
$$
    select (nullif(current_setting('request.jwt.claims', true), '')::jsonb -> 'user' ->> 'organization_id')::bigint;
$$;

grant execute on function auth.current_user_organization_id() to authenticated;

create or replace function auth.current_user_id()
returns bigint
language sql
security definer
as
$$
    select (nullif(current_setting('request.jwt.claims', true), '')::jsonb -> 'user' ->> 'user_id')::bigint;
$$;

create or replace function auth.current_user_role()
returns users.user_role
language sql
as
$$
    select (nullif(current_setting('request.jwt.claims', true), '')::jsonb -> 'user' ->> 'role')::users.user_role;
$$;

grant execute on function auth.current_user_role() to authenticated;
create or replace function auth.validate_current_user_org_access(
    _org_name text
) returns text
    language plpgsql
as
$$
declare
    _target_organization_id bigint;
begin
    if _org_name is null or _org_name = '' then
        return 'org_name_missing';
    end if;

    select organization_id
    into _target_organization_id
    from organizations.organization
    where org_name = _org_name;

    if _target_organization_id is null then
        return 'organization_not_found';
    end if;

    if auth.current_user_organization_id() != _target_organization_id then
        return 'organization_access_denied';
    end if;

    return null;
end;
$$;

create function auth.validate_login_input(_email text, _password text, _org_name text) returns text
    language plpgsql
as
$$
begin
    -- validate required fields
    if _org_name is null or _org_name = '' then
        return 'org_name_missing';
    end if;
    if _email is null or _email = '' then
        return 'email_missing';
    end if;
    if _password is null or _password = '' then
        return 'password_missing';
    end if;
    if not _email ilike '%@%' then
        return 'invalid_email_format';
    end if;

    -- Check if user exists in the organization
    if not exists (
        select 1
        from users.user u
        join organizations.organization o on o.organization_id = u.organization_id
        where email = lower(_email) and o.org_name = _org_name
    ) then
        return 'user_not_found';
    end if;

    return null;
end;
$$;

create or replace function auth.login(_email text, _password text, _org_name text, OUT validation_failure_message text, OUT access_token text, OUT refresh_token text) returns record
    language plpgsql
as
$$
declare
    _user users.user;
    _organization organizations.organization;
    _is_password_valid boolean;
    _access_token_claims jsonb;
    _refresh_token_claims jsonb;
    _user_role users.user_role;
    _user_status users.user_status;
    _access_token_secret text := config.item_from_app_settings('jwt_access_secret');
    _refresh_token_secret text := config.item_from_app_settings('jwt_refresh_secret');
    _access_token_expiration text := config.item_from_app_settings('jwt_access_expiration');
    _refresh_token_expiration text := config.item_from_app_settings('jwt_refresh_expiration');
begin
    -- Validate input
    validation_failure_message := auth.validate_login_input(_email, _password, _org_name);
    if validation_failure_message is not null then
        return;
    end if;

    -- Fetch user record
    select *
    into _user
    from users.user u
    join organizations.organization o on o.organization_id = u.organization_id
    where email = _email and o.org_name = _org_name;

    _user_status := users.user_status(_user.user_id);
    _user_role := users.user_role(_user.user_id);

    -- Check if user is active
    if _user_status <> 'active' then
        validation_failure_message := 'user_not_active';
        return;
    end if;

    -- Verify password
    _is_password_valid := _user.hashed_password = crypt(_password, _user.hashed_password);

    if not _is_password_valid then
        validation_failure_message := 'invalid_email_or_password';
        return;
    end if;

    -- Fetch organization record
    select *
    into _organization
    from organizations.organization
    where organization_id = _user.organization_id;

    -- Build JWT claims
    _access_token_claims := jsonb_build_object(
        'iat', extract(epoch from now())::int,
        'exp', extract(epoch from now())::int + _access_token_expiration::int,
        'token_type', 'access_token',
        'role', 'authenticated',
        'user', jsonb_build_object(
            'user_id', _user.user_id,
            'email', _user.email,
            'role', _user_role,
            'organization_id', _user.organization_id,
            'status', _user_status
        ),
        'organization', jsonb_build_object(
            'organization_id', _organization.organization_id,
            'org_name', _organization.org_name
        )
    );

    _refresh_token_claims := jsonb_build_object(
        'iat', extract(epoch from now())::int,
        'exp', extract(epoch from now())::int + _refresh_token_expiration::int,
        'user_id', _user.user_id,
        'token_type', 'refresh_token'
    );

    -- Generate JWT tokens
    access_token := auth.sign(_access_token_claims, _access_token_secret);
    refresh_token := auth.sign(_refresh_token_claims, _refresh_token_secret);

    return;
end;
$$;

create function auth.validate_refresh_tokens_input(_refresh_token text) returns text
    language plpgsql
as
$$
declare
    _refresh_token_secret text := config.item_from_app_settings('jwt_refresh_secret');
    _refresh_token_claims jsonb;
    _refresh_token_valid boolean;
    _user_id bigint;
    _user users.user;
    _user_status users.user_status;
begin
    if _refresh_token is null or _refresh_token = '' then
        return 'refresh_token_missing';
    end if;

    -- Validate refresh token
    select payload, valid
    into _refresh_token_claims, _refresh_token_valid
    from auth.verify(_refresh_token, _refresh_token_secret, 'HS256');

    if not _refresh_token_valid then
        return 'invalid_refresh_token';
    end if;

    if _refresh_token_claims->>'token_type' <> 'refresh_token' then
        return 'invalid_token_type';
    end if;

    _user_id := _refresh_token_claims->>'user_id';

    select *
    into _user
    from users.user
    where user_id = _user_id;


    if not found then
        return 'user_not_found';
    end if;

    _user_status := users.user_status(_user.user_id);

    if _user_status <> 'active' then
        return 'user_not_active';
    end if;

    return null;
end;
$$;

create function auth.refresh_tokens(_refresh_token text, OUT validation_failure_message text, OUT access_token text, OUT refresh_token text) returns record
    language plpgsql
as
$$
declare
    _user_id bigint;
    _user users.user;
    _organization organizations.organization;
    _new_access_token_claims jsonb;
    _new_refresh_token_claims jsonb;
    _user_role users.user_role;
    _user_status users.user_status;
    _access_token_secret text := config.item_from_app_settings('jwt_access_secret');
    _access_token_expiration text := config.item_from_app_settings('jwt_access_expiration');
    _refresh_token_secret text := config.item_from_app_settings('jwt_refresh_secret');
    _refresh_token_expiration text := config.item_from_app_settings('jwt_refresh_expiration');
    _refresh_token_claims jsonb;
begin
    -- validate refresh token
    validation_failure_message := auth.validate_refresh_tokens_input(_refresh_token);
    if validation_failure_message is not null then
        return;
    end if;

    -- Refresh token claims
    select payload
    into _refresh_token_claims
    from auth.verify(_refresh_token, _refresh_token_secret, 'HS256');

    _user_id := _refresh_token_claims->>'user_id';

    -- Fetch user record
    select *
    into _user
    from users.user
    where user_id = _user_id;

    _user_role := users.user_role(_user.user_id);
    _user_status := users.user_status(_user.user_id);

    -- Fetch organization record
    select *
    into _organization
    from organizations.organization
    where organization_id = _user.organization_id;

    -- Build JWT claims
    _new_access_token_claims := jsonb_build_object(
        'iat', extract(epoch from now())::int,
        'exp', extract(epoch from now())::int + _access_token_expiration::int,
        'role', 'authenticated',
        'token_type', 'access_token',
        'user', jsonb_build_object(
            'user_id', _user.user_id,
            'email', _user.email,
            'role', _user_role,
            'organization_id', _user.organization_id,
            'status', _user_status
        ),
        'organization', jsonb_build_object(
            'organization_id', _organization.organization_id,
            'org_name', _organization.org_name
        )
    );

    _new_refresh_token_claims := jsonb_build_object(
        'iat', extract(epoch from now())::int,
        'exp', extract(epoch from now())::int + _refresh_token_expiration::int,
        'user_id', _user.user_id,
        'token_type', 'refresh_token'
    );

    -- Generate JWT tokens
    access_token := auth.sign(_new_access_token_claims, _access_token_secret);
    refresh_token := auth.sign(_new_refresh_token_claims, _refresh_token_secret);

    return;
end;
$$;

create or replace function auth.generate_random_password() returns text
    language plpgsql
as
$$
declare
    _uppercase text := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    _lowercase text := 'abcdefghijklmnopqrstuvwxyz';
    _numbers text := '0123456789';
    _special_chars text := '!@#$%^&*(),.?":{}|<>';
    _password text := '';
    _i integer;
begin
    -- Add at least one character from each required category
    _password := _password || substr(_uppercase, (random() * length(_uppercase))::integer + 1, 1);
    _password := _password || substr(_lowercase, (random() * length(_lowercase))::integer + 1, 1);
    _password := _password || substr(_numbers, (random() * length(_numbers))::integer + 1, 1);
    _password := _password || substr(_special_chars, (random() * length(_special_chars))::integer + 1, 1);

    -- Add 8 more random characters to make it 12 characters long
    for _i in 1..8 loop
        case (random() * 4)::integer + 1
            when 1 then
                _password := _password || substr(_uppercase, (random() * length(_uppercase))::integer + 1, 1);
            when 2 then
                _password := _password || substr(_lowercase, (random() * length(_lowercase))::integer + 1, 1);
            when 3 then
                _password := _password || substr(_numbers, (random() * length(_numbers))::integer + 1, 1);
            when 4 then
                _password := _password || substr(_special_chars, (random() * length(_special_chars))::integer + 1, 1);
            else
        end case;
    end loop;

    -- Shuffle the password characters
    _password := array_to_string(
        array(
            select substr(_password, i, 1)
            from generate_series(1, length(_password)) i
            order by random()
        ),
        ''
    );

    return _password;
end;
$$;

-- Users
create or replace function users.user_organization_id(_user_id bigint) returns bigint
    language sql
as
$$
    select u.organization_id from users.user u where u.user_id = _user_id;
$$;

create or replace function users.user_role(_user_id bigint) returns users.user_role
    language sql
    security definer
as
$$
    select role
    from users.account_role
    where user_id = _user_id
    order by created_at desc
    limit 1;
$$;

grant execute on function users.user_role(bigint) to anon, authenticated;

create or replace function users.user_status(_user_id bigint) returns users.user_status
    language sql
    security definer
as
$$
    select status
    from users.account_status
    where user_id = _user_id
    order by created_at desc
    limit 1;
$$;

grant execute on function users.user_status(bigint) to anon, authenticated;

create function users.validate_create_user_input(_first_name text, _last_name text, _email text, _password text, _org_name text, _role users.user_role DEFAULT 'org_client') returns text
    language plpgsql
as
$$
declare
    _org_exists boolean;
    _user_exists boolean;
begin
    -- validate required fields
    if _first_name is null or _first_name = '' then
        return 'first_name_missing';
    end if;
    if _last_name is null or _last_name = '' then
        return 'last_name_missing';
    end if;
    if _email is null or _email = '' then
        return 'email_missing';
    end if;
    if _password is null or _password = '' then
        return 'password_missing';
    end if;
    if _org_name is null or _org_name = '' then
        return 'org_name_missing';
    end if;
    if _role not in ('org_client', 'org_admin', 'org_owner', 'g_admin', 'g_owner') then
        return 'invalid_role';
    end if;
    if not _email ~* '^[a-za-z0-9._%+-]+@[a-za-z0-9.-]+\.[a-za-z]{2,}$' then
        return 'invalid_email_format';
    end if;
    if length(_password) < 8 then
        return 'password_too_short';
    end if;
    if not (_password ~ '[A-Z]') then
        return 'password_missing_uppercase';
    end if;
    if not (_password ~ '[a-z]') then
        return 'password_missing_lowercase';
    end if;
    if not (_password ~ '[0-9]') then
        return 'password_missing_number';
    end if;
    if not (_password ~ '[!@#$%^&*(),.?":{}|<>]') then
        return 'password_missing_special_character';
    end if;

    -- check if organization exists
    select exists (
        select 1
        from organizations.organization
        where org_name = _org_name
    ) into _org_exists;

    if not _org_exists then
        return 'organization_not_found';
    end if;

    -- check if user exists in the organization
    select exists (
        select 1
        from users.user u
        join organizations.organization o on o.organization_id = u.organization_id
        where email = lower(_email) and o.org_name = _org_name
    ) into _user_exists;

    if _user_exists then
        return 'user_already_exists';
    end if;

    return null;
end;
$$;

create or replace function users.create_user(_first_name text, _last_name text, _email text, _password text, _org_name text, _role users.user_role DEFAULT 'org_client', OUT validation_failure_message text, OUT created_user jsonb) returns record
    language plpgsql
as
$$
declare
    _organization_id bigint;
    _new_user users.user;
    _hashed_password text;
begin
    -- Validate input
    validation_failure_message := users.validate_create_user_input(_first_name, _last_name, _email, _password, _org_name, _role);
    if validation_failure_message is not null then
        return;
    end if;

    -- Hash the password
    _hashed_password := crypt(_password, gen_salt('bf'));

    -- Get organization ID
    select organization_id
    into _organization_id
    from organizations.organization
    where org_name = _org_name;

    -- Insert user
    insert into users.user (
        organization_id,
        email,
        hashed_password,
        first_name,
        last_name
    ) values (
        _organization_id,
        lower(_email),
        _hashed_password,
        _first_name,
        _last_name
    ) returning * into _new_user;

    -- Insert account role
    insert into users.account_role (
        user_id,
        role
    ) values (
        _new_user.user_id,
        _role
    );

    -- Insert account status
    insert into users.account_status (
        user_id,
        status
    ) values (
        _new_user.user_id,
        'active'
    );

    -- Return user data
    created_user := jsonb_build_object(
        'user_id', _new_user.user_id,
        'organization_id', _new_user.organization_id,
        'first_name', _new_user.first_name,
        'last_name', _new_user.last_name,
        'email', _new_user.email,
        'role', users.user_role(_new_user.user_id),
        'status', users.user_status(_new_user.user_id),
        'created_at', _new_user.created_at,
        'updated_at', _new_user.updated_at
    );
end;
$$;

create function users.validate_create_user_status_input(_user_id bigint, _status users.user_status) returns text
    language plpgsql
    security definer
as
$$
begin
    if _user_id is null then
        return 'user_id_missing';
    end if;

    if _status not in ('active', 'inactive') then
        return 'invalid_status';
    end if;

    if not exists (
        select 1
        from users.user
        where user_id = _user_id and organization_id = auth.current_user_organization_id()
    ) then
        return 'user_not_found';
    end if;

    return null;
end;
$$;

create or replace function users.create_user_status(
    _user_id bigint,
    _status users.user_status,
    out validation_failure_message text,
    out created_status users.account_status
) returns record
    language plpgsql
    security definer
as
$$
declare
    _inserted_status users.account_status;
begin
    validation_failure_message := users.validate_create_user_status_input(_user_id, _status);
    if validation_failure_message is not null then
        return;
    end if;

    insert into users.account_status (
        user_id,
        status
    ) values (
        _user_id,
        _status
    ) returning * into _inserted_status;

    created_status := _inserted_status;

    return;
end;
$$;

-- AWS
create or replace function aws.generate_s3_presigned_url(
    _bucket_name text,
    _object_key text,
    _region text,
    _operation text default 'get',
    _expires_in_seconds int default 3600
)
returns text
language plpgsql
security definer
as $$
declare
    _aws_iam_s3_presigned_url_lambda_account_number text := config.get('aws_iam_s3_presigned_url_lambda_account_number');
    _function_name text;
    _lambda_payload json;
    _lambda_response record;
    _url text;
begin
    _function_name := 'arn:aws:lambda:' || _region || ':' || _aws_iam_s3_presigned_url_lambda_account_number || ':function:s3PresignedURL';

    _lambda_payload := json_build_object(
        'bucket', _bucket_name,
        'objectKey', _object_key,
        'region', _region,
        'operation', _operation,
        'expiresIn', _expires_in_seconds
    );

    _lambda_response := aws_lambda.invoke(
        function_name := _function_name,
        payload := _lambda_payload,
        region := _region
    );

    -- check if the call was successful
    if _lambda_response.status_code != 200 then
        raise exception 'lambda invocation failed with status code %', _lambda_response.status_code;
    end if;

    -- extract url from the payload
    _url := _lambda_response.payload ->> 'url';

    return _url;
end;
$$;

grant execute on function aws.generate_s3_presigned_url(text, text, text, text, int) to anon, authenticated;

-- Files
create or replace function files.get_file_extension_from_mimetype(_mime_type text)
returns text
language plpgsql
as $$
declare
    _extension text;
begin
    case _mime_type
        -- Images
        when 'image/jpeg' then _extension := 'jpeg';
        when 'image/jpg' then _extension := 'jpg';
        when 'image/png' then _extension := 'png';
        when 'image/gif' then _extension := 'gif';
        when 'image/bmp' then _extension := 'bmp';
        when 'image/tiff' then _extension := 'tiff';
        when 'image/webp' then _extension := 'webp';
        when 'image/svg+xml' then _extension := 'svg';
        when 'image/x-icon' then _extension := 'ico';
        
        -- Documents
        when 'application/pdf' then _extension := 'pdf';
        when 'application/msword' then _extension := 'doc';
        when 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' then _extension := 'docx';
        when 'application/vnd.ms-excel' then _extension := 'xls';
        when 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' then _extension := 'xlsx';
        when 'application/vnd.ms-powerpoint' then _extension := 'ppt';
        when 'application/vnd.openxmlformats-officedocument.presentationml.presentation' then _extension := 'pptx';
        when 'application/rtf' then _extension := 'rtf';
        
        -- Text
        when 'text/plain' then _extension := 'txt';
        when 'text/html' then _extension := 'html';
        when 'text/css' then _extension := 'css';
        when 'text/javascript' then _extension := 'js';
        when 'text/csv' then _extension := 'csv';
        when 'text/xml' then _extension := 'xml';
        when 'text/markdown' then _extension := 'md';
        
        -- Archives
        when 'application/zip' then _extension := 'zip';
        when 'application/x-rar-compressed' then _extension := 'rar';
        when 'application/x-7z-compressed' then _extension := '7z';
        when 'application/x-tar' then _extension := 'tar';
        when 'application/gzip' then _extension := 'gz';
        
        -- Audio
        when 'audio/mpeg' then _extension := 'mp3';
        when 'audio/wav' then _extension := 'wav';
        when 'audio/midi' then _extension := 'midi';
        when 'audio/ogg' then _extension := 'ogg';
        when 'audio/aac' then _extension := 'aac';
        when 'audio/webm' then _extension := 'weba';
        
        -- Video
        when 'video/mp4' then _extension := 'mp4';
        when 'video/mpeg' then _extension := 'mpeg';
        when 'video/quicktime' then _extension := 'mov';
        when 'video/x-msvideo' then _extension := 'avi';
        when 'video/webm' then _extension := 'webm';
        when 'video/3gpp' then _extension := '3gp';
        when 'video/x-matroska' then _extension := 'mkv';
        
        -- Fonts
        when 'font/ttf' then _extension := 'ttf';
        when 'font/otf' then _extension := 'otf';
        when 'font/woff' then _extension := 'woff';
        when 'font/woff2' then _extension := 'woff2';
        
        -- Programming
        when 'application/json' then _extension := 'json';
        when 'application/xml' then _extension := 'xml';
        when 'application/x-yaml' then _extension := 'yaml';
        when 'application/x-python-code' then _extension := 'py';
        when 'application/x-java-source' then _extension := 'java';
        when 'application/x-httpd-php' then _extension := 'php';
        
        -- Database
        when 'application/sql' then _extension := 'sql';
        when 'application/x-sqlite3' then _extension := 'sqlite';
        
        -- Adobe
        when 'application/x-photoshop' then _extension := 'psd';
        when 'application/illustrator' then _extension := 'ai';
        when 'application/x-indesign' then _extension := 'indd';
        
        -- CAD and 3D
        when 'application/x-autocad' then _extension := 'dwg';
        when 'model/stl' then _extension := 'stl';
        when 'model/obj' then _extension := 'obj';
        
        -- Others
        when 'application/octet-stream' then _extension := 'bin';
        when 'application/x-executable' then _extension := 'exe';
        when 'application/x-shockwave-flash' then _extension := 'swf';
        
        else
            _extension := 'bin';  -- Default for unknown types
    end case;

    return _extension;
end;
$$;

create or replace function files.generate_object_key(
    _organization_id bigint,
    _file_category text,
    _mime_type text,
    _file_name text default null,
    _parent_entity_id bigint default null
) returns text
    language plpgsql
as $$
declare
    _timestamp bigint := extract(epoch from now())::bigint::text;
    _object_key text;
    _base_file_name text;
    _extension text := files.get_file_extension_from_mimetype(_mime_type);
begin
    _object_key := _organization_id || '/' || _file_category;

    if _parent_entity_id is not null then
        _object_key := _object_key || '/' || _parent_entity_id;
    end if;

    if _file_name is not null and _file_name != '' then
        _base_file_name := regexp_replace(split_part(_file_name, '.', 1), '[^a-zA-Z0-9\-_]', '-', 'g');

        -- Fallback to file_id if the base file name is empty
        if _base_file_name = '' or _base_file_name = '-' then
            _base_file_name := _timestamp;
        end if;

        _object_key := _object_key || '/' || _base_file_name || '_' || _timestamp;
    else
        -- Fallback to just file_id if no name provided
        _object_key := _object_key || '/' || '_' || _timestamp;
    end if;

    if _extension is not null and _extension != '' then
        _object_key := _object_key || '.' || _extension;
    end if;

    return _object_key;
end;
$$;

-- Api
create function api.login(email text, password text, org_name text) returns jsonb
    security definer
    language plpgsql
as
$$
declare
    _login_result record;
begin
    _login_result := auth.login(email, password, org_name);
    if _login_result.validation_failure_message is not null then
        raise exception 'Login Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _login_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'access_token', _login_result.access_token,
       'refresh_token', _login_result.refresh_token
    );
end;
$$;

grant execute on function api.login(text, text, text) to anon;

create function api.refresh_tokens(refresh_token text) returns jsonb
    security definer
    language plpgsql
as
$$
declare
    _refresh_token_result record;
begin
    _refresh_token_result := auth.refresh_tokens(refresh_token);
    if _refresh_token_result.validation_failure_message is not null then
        raise exception 'Refresh Tokens Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _refresh_token_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'access_token', _refresh_token_result.access_token,
        'refresh_token', _refresh_token_result.refresh_token
    );
end;
$$;

grant execute on function api.refresh_tokens(text) to anon;

create function api.register_client(first_name text, last_name text, email text, password text, org_name text) returns jsonb
    security definer
    language plpgsql
as
$$
declare
    _create_user_result record;
begin
    _create_user_result := users.create_user(first_name, last_name, email, password, org_name);
    if _create_user_result.validation_failure_message is not null then
        raise exception 'Client Registration Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_user_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'user', _create_user_result.created_user
    );
end;
$$;

grant execute on function api.register_client(text, text, text, text, text) to anon;

create or replace function api.create_client(first_name text, last_name text, email text, org_name text) returns jsonb
    security definer
    language plpgsql
as
$$
declare
    _org_access_validation_failure_message text;
    _password text;
    _create_user_result record;
begin
    _org_access_validation_failure_message := auth.validate_current_user_org_access(org_name);
    if _org_access_validation_failure_message is not null then
        raise exception 'Organization Access Denied'
            using
                detail = 'The organization you are requesting to create a client for does not match the organization you are authenticated as',
                hint = _org_access_validation_failure_message;
    end if;

    _password := auth.generate_random_password();
    _create_user_result := users.create_user(
        first_name,
        last_name,
        email,
        _password,
        org_name,
        'org_client'
    );

    if _create_user_result.validation_failure_message is not null then
        raise exception 'Client Creation Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_user_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'user', _create_user_result.created_user
    );
end;
$$;

grant execute on function api.create_client(text, text, text, text) to authenticated;

create or replace function api.update_user_status(user_id bigint, status users.user_status) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _target_user_role users.user_role;
    _current_user_role users.user_role;
    _create_user_status_result record;
begin
    -- Verify user has permission to update the target user's status
    _target_user_role := users.user_role(user_id);
    _current_user_role := auth.current_user_role();
    if (_target_user_role = 'org_client' and _current_user_role not in ('org_admin', 'org_owner')) or (_target_user_role = 'org_admin' and _current_user_role != 'org_owner') then
        raise exception 'User Status Update Failed'
            using
                detail = 'You are not authorized to update the status of this user',
                hint = 'unauthorized';
    end if;

    _create_user_status_result := users.create_user_status(user_id, status);
    if _create_user_status_result.validation_failure_message is not null then
        raise exception 'User Status Update Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_user_status_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'user_id', (_create_user_status_result.created_status).user_id,
        'status', (_create_user_status_result.created_status).status
    );
end;
$$;

grant execute on function api.update_user_status(bigint, users.user_status) to authenticated;

-- Views
-- Organization
create or replace view api.organizations as
select
    o.organization_id,
    o.name,
    o.org_name,
    case 
        when f.file_id is not null then 
            aws.generate_s3_presigned_url(
                f.bucket,
                f.object_key,
                f.region,
                'GET',
                3600
            )
        else 
            null
    end as logo_url,
    o.created_at,
    o.updated_at
from organizations.organization o
left join files.file f on o.logo_file_id = f.file_id;

grant select on api.organizations to anon;

-- Clients
create or replace view api.clients as
select
    u.user_id,
    u.organization_id,
    u.email,
    u.first_name,
    u.last_name,
    concat(u.first_name, ' ', u.last_name) as full_name,
    users.user_role(u.user_id) as role,
    users.user_status(u.user_id) as status,
    case
        when f.file_id is not null then
            aws.generate_s3_presigned_url(
                f.bucket,
                f.object_key,
                f.region,
                'GET',
                3600
            )
    end as profile_picture_url,
    u.created_at,
    u.updated_at
from users.user u
left join files.file f on u.profile_picture_file_id = f.file_id
where users.user_role(u.user_id) = 'org_client' and u.organization_id = auth.current_user_organization_id();

grant select on api.clients to authenticated;

commit;

-- Seed the database
begin;

-- Ask Ben for these values
insert into config.config (key, value) values
    ('aws_iam_s3_presigned_url_lambda_account_number', '730335337751');


insert into organizations.organization (organization_id, name, org_name) values
    (12345678, 'Glovee', 'glovee'),
    (87654321, 'Test Immigration Consultanting Inc.', 'test');

insert into organizations.organization_config (organization_id, s3_bucket, s3_region) values
    (12345678, 'glovee-ca-central-1-bucket', 'ca-central-1'),
    (87654321, 'glovee-ca-central-1-bucket', 'ca-central-1');

insert into files.file (file_id, name, object_key, bucket, region, mime_type, size, organization_id) values
    (73059950026579, 'glovee_logo.jpeg', '12345678/organization_logo/glovee_logo_1730599469.jpeg', 'glovee-ca-central-1-bucket', 'ca-central-1', 'image/jpg', 3268, 12345678);

update organizations.organization set logo_file_id = 73059950026579 where organization_id = 12345678;


-- Seed test users (password is 'Test@123')
insert into users.user (
    user_id,
    organization_id,
    email,
    hashed_password,
    first_name,
    last_name
) values
    (1111111, 12345678, 'admin@glovee.com', crypt('Test@123', gen_salt('bf')), 'Admin', 'User'),
    (2222222, 12345678, 'client@glovee.com', crypt('Test@123', gen_salt('bf')), 'Client', 'User');

insert into users.account_role (user_id, role) values
    (1111111, 'org_admin'),
    (2222222, 'org_client');

insert into users.account_status (user_id, status) values
    (1111111, 'active'),
    (2222222, 'active');

commit;
