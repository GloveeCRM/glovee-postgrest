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

-- Organization
create or replace function organizations.org_id_by_org_name(_org_name text) returns bigint
    language sql
as
$$
    select organization_id from organizations.organization where org_name = _org_name;
$$;

create or replace function organizations.config_by_org_id(_organization_id bigint) returns organizations.organization_config
    language plpgsql
as
$$
declare
    _config organizations.organization_config;
begin
    select * into _config from organizations.organization_config where organization_id = _organization_id;
    return _config;
end;
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

grant execute on function auth.current_user_id() to authenticated;

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

create or replace function auth.login(_email text, _password text, _org_name text, out validation_failure_message text, out access_token text, OUT refresh_token text) returns record
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

create function auth.refresh_tokens(_refresh_token text, out validation_failure_message text, out access_token text, out refresh_token text) returns record
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

create or replace function users.profile_picture_url(_user_id bigint) returns text
    language plpgsql
    security definer
as
$$
declare
    _file_id bigint;
begin
    select profile_picture_file_id
    into _file_id
    from users.user
    where user_id = _user_id;

    return files.generate_url(_file_id);
end;
$$;

grant execute on function users.profile_picture_url(bigint) to authenticated;

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

create or replace function users.create_user(
    _first_name text,
    _last_name text,
    _email text,
    _password text,
    _org_name text,
    _role users.user_role default 'org_client',
    out validation_failure_message text,
    out created_user jsonb
) returns record
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
    ) returning * into created_status;

    return;
end;
$$;

create or replace function users.validate_update_user_input(_user_id bigint, _email text default null, _first_name text default null, _last_name text default null) returns text
    language plpgsql
    security definer
as
$$
begin
    if _user_id is null then
        return 'user_id_missing';
    end if;

    if _email is not null and not _email ilike '%@%' then
        return 'invalid_email_format';
    end if;

    if _first_name is not null and _first_name = '' then
        return 'first_name_missing';
    end if;

    if _last_name is not null and _last_name = '' then
        return 'last_name_missing';
    end if;

    if _email is not null and exists (
        select 1
        from users.user
        where email = lower(_email) and organization_id = auth.current_user_organization_id()
        and user_id != _user_id
    ) then
        return 'email_already_in_use';
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

create or replace function users.update_user(
    _user_id bigint,
    _email text default null,
    _first_name text default null,
    _last_name text default null,
    out validation_failure_message text,
    out updated_user jsonb
) returns record
    language plpgsql
    security definer
as
$$
declare
    _updated_user users.user;
begin
    validation_failure_message := users.validate_update_user_input(_user_id, _email, _first_name, _last_name);
    if validation_failure_message is not null then
        return;
    end if;

    update users.user u
    set email = coalesce(_email, u.email),
        first_name = coalesce(_first_name, u.first_name),
        last_name = coalesce(_last_name, u.last_name),
        updated_at = now()
    where user_id = _user_id and organization_id = auth.current_user_organization_id()
    returning to_jsonb(row_to_json(u)) - 'hashed_password' into updated_user;

    updated_user := updated_user || jsonb_build_object(
        'role', users.user_role(_user_id),
        'status', users.user_status(_user_id)
    );

    return;
end;
$$;

create or replace function users.validate_create_user_profile_picture_input(
    _user_id bigint,
    _file_id bigint
) returns text
    language plpgsql
as
$$
begin
    if _user_id is null or _user_id <= 0 then
        return 'missing_user_id';
    end if;

    if _file_id is null or _file_id <= 0 then
        return 'missing_file_id';
    end if;

    if not exists (
        select 1 
        from files.file
        where file_id = _file_id
    ) then
        return 'file_not_found';
    end if;

    return null;
end;
$$;

create or replace function users.create_user_profile_picture(
    _user_id bigint, 
    _file_id bigint, 
    out validation_failure_message text,
    out created_user_profile_picture users.user
) returns record
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := users.validate_create_user_profile_picture_input(_user_id, _file_id);
    if validation_failure_message is not null then
        return;
    end if;

    update users.user 
    set profile_picture_file_id = _file_id,
        updated_at = now()
    where user_id = _user_id
    returning * into created_user_profile_picture;
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
create or replace function files.generate_url(_file_id bigint) returns text
    language plpgsql
    security definer
as
$$
declare
    _file files.file;
    _target_org_id bigint := auth.current_user_organization_id();
    _organization_config organizations.organization_config := organizations.config_by_org_id(_target_org_id);
begin
    select *
    into _file
    from files.file
    where file_id = _file_id
    and organization_id = _target_org_id;

    if not found then
        return null;
    end if;

    return aws.generate_s3_presigned_url(
        _organization_config.s3_bucket,
        _file.object_key,
        _organization_config.s3_region,
        'GET',
        360
    );
end;
$$;

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

create or replace function files.validate_create_file_input(
    _object_key text,
    _file_name text,
    _bucket text,
    _region text,
    _mime_type text,
    _size bigint,
    _organization_id bigint,
    _created_by bigint
) returns text
language plpgsql
as
$$
declare
    _target_org_config organizations.organization_config := organizations.config_by_org_id(_organization_id);
begin
    if _object_key is null or _object_key = '' then
        return 'missing_object_key';
    end if;

    if _file_name is null or _file_name = '' then
        return 'missing_file_name';
    end if;

    if _bucket is null or _bucket = '' then
        return 'missing_bucket';
    end if;

    if _bucket != _target_org_config.s3_bucket then
        return 'invalid_bucket';
    end if;

    if _region is null or _region = '' then
        return 'missing_region';
    end if;

    if _region != _target_org_config.s3_region then
        return 'invalid_region';
    end if;

    if _mime_type is null or _mime_type = '' then
        return 'missing_mime_type';
    end if;

    if _size is null or _size <= 0 then
        return 'missing_size';
    end if;

    if _organization_id is null or _organization_id <= 0 then
        return 'missing_organization_id';
    end if;

    if _created_by is null or _created_by <= 0 then
        return 'missing_created_by';
    end if;

    return null;
end;
$$;

create or replace function files.create_file(
    _object_key text,
    _file_name text,
    _bucket text,
    _region text,
    _mime_type text,
    _size bigint,
    _organization_id bigint,
    _created_by bigint,
    _metadata jsonb default null,
    _version bigint default 1,
    _is_public boolean default false,
    out validation_failure_message text,
    out created_file files.file
) returns record
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := files.validate_create_file_input(
        _object_key,
        _file_name,
        _bucket,
        _region,
        _mime_type,
        _size,
        _organization_id,
        _created_by
    );
    if validation_failure_message is not null then
        return;
    end if;

    insert into files.file (
        object_key,
        name,
        bucket,
        region,
        mime_type,
        size,
        organization_id,
        created_by,
        version,
        is_public,
        metadata
    ) values (
        _object_key,
        _file_name,
        _bucket,
        _region,
        _mime_type,
        _size,
        _organization_id,
        _created_by,
        _version,
        _is_public,
        _metadata
    ) returning * into created_file;

    return;
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

create or replace function api.update_user(user_id bigint, email text default null, first_name text default null, last_name text default null) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_id bigint := auth.current_user_id();
    _target_user_role users.user_role := users.user_role(user_id);
    _current_user_role users.user_role := auth.current_user_role();
    _update_user_result record;
begin
    -- Verify user has permission to update the target user
    if (_current_user_role = 'org_client' and user_id != _current_user_id) 
    or (_current_user_role = 'org_admin' and _target_user_role = 'org_admin' and user_id != _current_user_id)
    or (_target_user_role = 'org_owner' and _current_user_role != 'org_owner') 
    then
        raise exception 'User Update Failed'
            using
                detail = 'You are not authorized to update this user',
                hint = 'unauthorized';
    end if;

    _update_user_result := users.update_user(user_id, email, first_name, last_name);
    if _update_user_result.validation_failure_message is not null then
        raise exception 'User Update Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _update_user_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'user', _update_user_result.updated_user
    );
end;
$$;

grant execute on function api.update_user(bigint, text, text, text) to authenticated;

create or replace function api.profile_picture_upload_url(org_name text, user_id bigint, file_name text default null, mime_type text default null) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_id bigint := auth.current_user_id();
    _current_user_role users.user_role := auth.current_user_role();
    _target_user_role users.user_role := users.user_role(user_id);
    _target_org_id bigint := organizations.org_id_by_org_name(org_name);
    _object_key text;
    _org_config organizations.organization_config;
begin
    if (_current_user_role = 'org_client' and user_id != _current_user_id)
    or (_current_user_role = 'org_admin' and _target_user_role != 'org_client' and user_id != _current_user_id) 
    or (_target_user_role = 'org_owner' and _current_user_role != 'org_owner') then
        raise exception 'Profile Picture Upload URL Failed'
            using
                detail = 'You are not authorized to update this user',
                hint = 'unauthorized';
    end if;

    _object_key := files.generate_object_key(
        _target_org_id,
        'profile_picture',
        mime_type,
        file_name,
        user_id
    );

    _org_config := organizations.config_by_org_id(_target_org_id);

    return jsonb_build_object(
        'url', aws.generate_s3_presigned_url(
            _org_config.s3_bucket,
            _object_key,
            _org_config.s3_region,
            'PUT',
            3600
        ),
        'object_key', _object_key
    );
end;
$$;

grant execute on function api.profile_picture_upload_url(text,  bigint, text, text) to authenticated;

create or replace function api.create_user_profile_picture(
    user_id bigint, 
    object_key text, 
    file_name text, 
    mime_type text, 
    size bigint, 
    metadata jsonb default null
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _user_org_config organizations.organization_config;
    _create_file_result record;
    _updated_user_result record;
begin
    _user_org_config := organizations.config_by_org_id(auth.current_user_organization_id());
    
    _create_file_result := files.create_file(
        object_key,
        file_name,
        _user_org_config.s3_bucket,
        _user_org_config.s3_region,
        mime_type,
        size,
        auth.current_user_organization_id(),
        auth.current_user_id(),
        metadata
    );

    if _create_file_result.validation_failure_message is not null then
        raise exception 'User Profile Picture Creation Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_file_result.validation_failure_message;
    end if;

    -- Update the user's profile picture file id
    _updated_user_result := users.create_user_profile_picture(user_id, (_create_file_result.created_file).file_id);
    if _updated_user_result.validation_failure_message is not null then
        raise exception 'User Profile Picture Update Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _updated_user_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'url', aws.generate_s3_presigned_url(
            _user_org_config.s3_bucket,
            object_key,
            _user_org_config.s3_region,
            'GET',
            3600
        )
    );
end;
$$;

grant execute on function api.create_user_profile_picture(bigint, text, text, text, bigint, jsonb) to authenticated;

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
where
    users.user_role(u.user_id) = 'org_client' 
and 
    u.organization_id = auth.current_user_organization_id()
and (
    (
        auth.current_user_role() = 'org_client' 
        and u.user_id = auth.current_user_id()
    )
    or auth.current_user_role() in ('org_admin', 'org_owner')
);

grant select on api.clients to authenticated;

-- Applications
create schema if not exists applications;

-- Create application table
create table applications.application (
    application_id bigint default utils.generate_random_id() not null primary key,
    user_id bigint not null references users.user(user_id) on delete set null,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now()
);

create table applications.application_update (
    application_update_id bigint default utils.generate_random_id() not null primary key,
    application_id bigint not null references applications.application(application_id) on delete cascade,
    title text not null,
    description text,
    created_by bigint not null references users.user(user_id) on delete set null,
    created_at timestamp with time zone not null default now()
);

create table applications.application_update_file (
    application_update_file_id bigint default utils.generate_random_id() not null primary key,
    application_update_id bigint not null references applications.application_update(application_update_id) on delete cascade,
    file_id bigint not null references files.file(file_id) on delete cascade,
    created_at timestamp with time zone not null default now()
);


create or replace function applications.application_user_id(_application_id bigint) returns bigint
    language sql
as
$$
    select a.user_id 
    from applications.application a 
    where a.application_id = _application_id;
$$;

create or replace function applications.application_organization_id(_application_id bigint) returns bigint
    language sql
as
$$
    select u.organization_id
    from applications.application a
    join users.user u on a.user_id = u.user_id
    where a.application_id = _application_id;
$$;

create or replace function applications.validate_create_application_input(
    _user_id bigint
) returns text
    language plpgsql
as
$$
begin
    if _user_id is null or _user_id <= 0 then
        return 'missing_user_id';
    end if;

    return null;
end;
$$;

create or replace function applications.create_application(
    _user_id bigint,
    out validation_failure_message text,
    out created_application applications.application
)
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := applications.validate_create_application_input(_user_id);
    if validation_failure_message is not null then
        return;
    end if;

    insert into applications.application (user_id)
    values (_user_id)
    returning * into created_application;

    return;
end;
$$;

-- Application Files
create table applications.application_file (
    application_file_id bigint default utils.generate_random_id() not null primary key,
    application_id bigint not null references applications.application(application_id) on delete cascade,
    file_id bigint not null references files.file(file_id) on delete cascade,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now(),
    created_by bigint not null references users.user(user_id) on delete set null
);

create or replace function applications.validate_create_application_file_input(
    _application_id bigint,
    _file_id bigint,
    _created_by bigint
) returns text
    language plpgsql
as
$$
begin
    if _application_id is null or _application_id <= 0 then
        return 'missing_application_id';
    end if;

    if _file_id is null or _file_id <= 0 then
        return 'missing_file_id';
    end if;

    if _created_by is null or _created_by <= 0 then
        return 'missing_created_by';
    end if;

    if not exists (
        select 1 
        from users.user u
        where u.user_id = _created_by
        and u.organization_id = auth.current_user_organization_id()
    ) then
        return 'user_not_found';
    end if;

    if not exists (
        select 1
        from files.file f
        where f.file_id = _file_id
        and f.organization_id = auth.current_user_organization_id()
    ) then
        return 'file_not_found';
    end if;

    if not exists (
        select 1
        from applications.application a
        join users.user u on a.user_id = u.user_id
        where a.application_id = _application_id
        and u.organization_id = auth.current_user_organization_id()
    ) then
        return 'application_not_found';
    end if;

    return null;
end;
$$;

create or replace function applications.create_application_file(
    _application_id bigint,
    _file_id bigint,
    _created_by bigint,
    out validation_failure_message text,
    out created_application_file applications.application_file
)
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := applications.validate_create_application_file_input(_application_id, _file_id, _created_by);
    if validation_failure_message is not null then
        return;
    end if;

    insert into applications.application_file 
    (application_id, file_id, created_by)
    values (_application_id, _file_id, _created_by)
    returning * 
    into created_application_file;

    return;
end;
$$;

create or replace function applications.validate_create_application_update_input(
    _application_id bigint,
    _title text,
    _created_by bigint,
    _file_ids bigint[] default null
) returns text
    language plpgsql
as
$$
declare
    _current_user_org_id bigint := auth.current_user_organization_id();
    _target_org_id bigint := applications.application_organization_id(_application_id);
begin
    if _application_id is null or _application_id <= 0 then
        return 'missing_application_id';
    end if;

    if _title is null or _title = '' then
        return 'missing_title';
    end if;

    if _created_by is null or _created_by <= 0 then
        return 'missing_created_by';
    end if;

    if not exists (
        select 1
        from 
            applications.application a
        where 
            a.application_id = _application_id
        and 
            _target_org_id = _current_user_org_id
    ) then
        return 'application_not_found';
    end if;

    if not exists (
        select 1
        from users.user u
        where u.user_id = _created_by
        and u.organization_id = _target_org_id
    ) then
        return 'user_not_found';
    end if;

    if _file_ids is not null then
        if not exists (
            select 1
            from files.file f
            where f.file_id = any(_file_ids)
            and f.organization_id = _target_org_id
        ) then
            return 'file_not_found';
        end if;
    end if;

    return null;
end;
$$;

create or replace function applications.create_application_update(
    _application_id bigint,
    _title text,
    _created_by bigint,
    _description text default null,
    _file_ids bigint[] default null,
    out validation_failure_message text,
    out created_application_update applications.application_update
) returns record
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := applications.validate_create_application_update_input(_application_id, _title, _created_by, _file_ids);
    if validation_failure_message is not null then
        return;
    end if;

    -- Insert the application update
    insert into 
        applications.application_update (application_id, title, description, created_by)
    values 
        (_application_id, _title, _description, _created_by)
    returning 
        * 
    into created_application_update;

    -- Insert the application update files
    if _file_ids is not null then
        insert into 
            applications.application_update_file (application_update_id, file_id)
        select
            created_application_update.application_update_id,
            unnest(_file_ids);
    end if;

    return;
end;
$$;


create or replace function api.create_application(user_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_org_id bigint;
    _target_user_org_id bigint;
    _create_application_result record;
begin
    _current_user_org_id := auth.current_user_organization_id();
    _target_user_org_id := users.user_organization_id(user_id);
    if _target_user_org_id is null or _target_user_org_id != _current_user_org_id then
        raise exception 'Application Creation Failed'
            using
                detail = 'The user with the provided user_id does not exist in the organization of the authenticated user',
                hint = 'user_not_found';
    end if;

    _create_application_result := applications.create_application(user_id);
    if _create_application_result.validation_failure_message is not null then
        raise exception 'Application Creation Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_application_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'application', _create_application_result.created_application
    );
end;
$$;

grant execute on function api.create_application(bigint) to authenticated;

-- Application Files
create or replace function applications.application_organization_id(_application_id bigint) returns bigint
    language sql
as
$$
    select u.organization_id
    from applications.application a
    join users.user u on a.user_id = u.user_id
    where a.application_id = _application_id;
$$;

create or replace function api.application_file_upload_url(
    application_id bigint,
    file_name text,
    mime_type text
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_org_id bigint := auth.current_user_organization_id();
    _current_user_id bigint := auth.current_user_id();
    _current_user_role users.user_role := auth.current_user_role();
    _target_user_id bigint := applications.application_user_id(application_id);
    _target_org_id bigint := applications.application_organization_id(application_id);
    _org_config organizations.organization_config;
    _object_key text;
begin
    -- Check if the application's owner is the current user or the current user is an admin or owner in the organization of the application
    if (_current_user_role = 'org_client' and _target_user_id != _current_user_id)
    or (_current_user_role in ('org_admin', 'org_owner') and _target_org_id != _current_org_id) then
        raise exception 'Application File Creation Failed'
            using
                detail = 'You are not authorized to create an application file for this application',
                hint = 'unauthorized';
    end if;

    _object_key := files.generate_object_key(
        _current_org_id,
        'application_file',
        mime_type,
        file_name,
        application_id
    );

    _org_config := organizations.config_by_org_id(_current_org_id);

    return jsonb_build_object(
        'url', aws.generate_s3_presigned_url(
            _org_config.s3_bucket,
            _object_key,
            _org_config.s3_region,
            'PUT',
            3600
        ),
        'object_key', _object_key
    );
end;
$$;

grant execute on function api.application_file_upload_url(bigint, text, text) to authenticated;

create or replace function api.create_application_file(
    application_id bigint,
    object_key text,
    file_name text,
    mime_type text,
    size bigint,
    metadata jsonb default null
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_id bigint := auth.current_user_id();
    _current_user_org_id bigint := auth.current_user_organization_id();
    _target_user_id bigint := applications.application_user_id(application_id);
    _current_user_role users.user_role := auth.current_user_role();
    _user_org_config organizations.organization_config;
    _create_file_result record;
    _create_application_file_result record;
    _create_application_update_result record;
begin
    if _current_user_role = 'org_client' and _target_user_id != _current_user_id then
        raise exception 'Application File Creation Failed'
            using
                detail = 'You are not authorized to create an application file for this application',
                hint = 'unauthorized';
    end if;

    _user_org_config := organizations.config_by_org_id(_current_user_org_id);

    _create_file_result := files.create_file(
        object_key,
        file_name,
        _user_org_config.s3_bucket,
        _user_org_config.s3_region,
        mime_type,
        size,
        _current_user_org_id,
        _current_user_id,
        metadata
    );

    if _create_file_result.validation_failure_message is not null then
        raise exception 'Application File Creation Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_file_result.validation_failure_message;
    end if;

    _create_application_file_result := applications.create_application_file(application_id, (_create_file_result.created_file).file_id, _current_user_id);
    if _create_application_file_result.validation_failure_message is not null then
        raise exception 'Application File Creation Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_application_file_result.validation_failure_message;
    end if;

    _create_application_update_result := applications.create_application_update(
        application_id,
        'File Uploaded',
        _current_user_id, 
        null, 
        array[(_create_file_result.created_file).file_id]
    );
    if _create_application_update_result.validation_failure_message is not null then
        raise exception 'Application File Creation Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_application_update_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'application_file', _create_application_file_result.created_application_file
    );
end;
$$;

grant execute on function api.create_application_file(bigint, text, text, text, bigint, jsonb) to authenticated;

create or replace function api.application_files_by_client(application_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_id bigint := auth.current_user_id();
    _current_user_org_id bigint := auth.current_user_organization_id();
    _current_user_role users.user_role := auth.current_user_role();
    _organization_config organizations.organization_config := organizations.config_by_org_id(_current_user_org_id);
    _application_files jsonb;
begin
    if (_current_user_role = 'org_client' and applications.application_user_id($1) != _current_user_id)
    or (_current_user_role in ('org_admin', 'org_owner') and applications.application_organization_id($1) != _current_user_org_id) then
        raise exception 'Application Files Retrieval Failed'
            using
                detail = 'You are not authorized to retrieve the application files for this application',
                hint = 'unauthorized';
    end if;

    select
        jsonb_agg(
            jsonb_build_object(
                'file_id', f.file_id,
                'name', f.name,
                'mime_type', f.mime_type,
                'size', f.size,
                'url', aws.generate_s3_presigned_url(
                    _organization_config.s3_bucket,
                    f.object_key,
                    _organization_config.s3_region,
                    'GET',
                    3600
                ),
                'metadata', f.metadata,
                'created_at', af.created_at,
                'updated_at', af.updated_at
            )
        )
    into
        _application_files
    from
        applications.application_file af
    join
        files.file f
    on
        af.file_id = f.file_id
    where
        af.application_id = $1
    and
        users.user_role(af.created_by) = 'org_client';

    return jsonb_build_object(
        'application_files', coalesce(_application_files, '[]'::jsonb)
    );
end;
$$;

grant execute on function api.application_files_by_client(bigint) to authenticated;

create or replace function api.application_files_by_admin(application_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_id bigint := auth.current_user_id();
    _current_user_org_id bigint := auth.current_user_organization_id();
    _current_user_role users.user_role := auth.current_user_role();
    _organization_config organizations.organization_config := organizations.config_by_org_id(_current_user_org_id);
    _application_files jsonb;
begin
    if (_current_user_role = 'org_client' and applications.application_user_id($1) != _current_user_id)
    or (_current_user_role in ('org_admin', 'org_owner') and applications.application_organization_id($1) != _current_user_org_id) then
        raise exception 'Application Files Retrieval Failed'
            using
                detail = 'You are not authorized to retrieve the application files for this application',
                hint = 'unauthorized';
    end if;

    select
        jsonb_agg(
            jsonb_build_object(
                'file_id', f.file_id,
                'name', f.name,
                'mime_type', f.mime_type,
                'size', f.size,
                'url', aws.generate_s3_presigned_url(
                    _organization_config.s3_bucket,
                    f.object_key,
                    _organization_config.s3_region,
                    'GET',
                    3600
                ),
                'metadata', f.metadata,
                'created_at', af.created_at,
                'updated_at', af.updated_at
            )
        )
    into
        _application_files
    from
        applications.application_file af
    join
        files.file f
    on
        af.file_id = f.file_id
    where
        af.application_id = $1
    and
        users.user_role(af.created_by) in ('org_admin', 'org_owner');

    return jsonb_build_object(
        'application_files', coalesce(_application_files, '[]'::jsonb)
    );
end;
$$;

grant execute on function api.application_files_by_admin(bigint) to authenticated;

create or replace function api.application_updates(application_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_id bigint := auth.current_user_id();
    _current_user_org_id bigint := auth.current_user_organization_id();
    _current_user_role users.user_role := auth.current_user_role();
    _organization_config organizations.organization_config := organizations.config_by_org_id(_current_user_org_id);
    _application_updates jsonb;
begin
    if (_current_user_role = 'org_client' and applications.application_user_id($1) != _current_user_id)
    or (_current_user_role in ('org_admin', 'org_owner') and applications.application_organization_id($1) != _current_user_org_id) then
        raise exception 'Application Updates Retrieval Failed'
            using
                detail = 'You are not authorized to retrieve the application updates for this application',
                hint = 'unauthorized';
    end if;

    with update_files as (
        select 
            au.application_update_id,
            jsonb_agg(
                jsonb_build_object(
                    'file_id', f.file_id,
                    'name', f.name,
                    'mime_type', f.mime_type,
                    'url', aws.generate_s3_presigned_url(
                        _organization_config.s3_bucket,
                        f.object_key,
                        _organization_config.s3_region,
                        'GET',
                        3600
                    )
                )
            ) as files
        from 
            applications.application_update au
        join
            applications.application_update_file aup
        on
            au.application_update_id = aup.application_update_id
        join
            files.file f
        on
            aup.file_id = f.file_id
        where
            au.application_id = $1
        group by
            au.application_update_id
    )
    select
        jsonb_agg(
            jsonb_build_object(
                'application_update_id', au.application_update_id,
                'title', au.title,
                'description', au.description,
                'created_at', au.created_at,
                'created_by', jsonb_build_object(
                    'user_id', u.user_id,
                    'role', users.user_role(au.created_by),
                    'email', u.email,
                    'first_name', u.first_name,
                    'last_name', u.last_name,
                    'full_name', concat(u.first_name, ' ', u.last_name)
                ),
                'files', coalesce(uf.files, '[]'::jsonb)
            )
            order by au.created_at desc
        )
    into 
        _application_updates
    from 
        applications.application_update au
    join
        users.user u
    on
        au.created_by = u.user_id
    left join
        update_files uf
    on
        au.application_update_id = uf.application_update_id
    where
        au.application_id = $1;

    return jsonb_build_object(
        'application_updates', coalesce(_application_updates, '[]'::jsonb)
    );
end;
$$;

grant execute on function api.application_updates(bigint) to authenticated;

-- Views
create or replace view api.applications as
select
    a.application_id,
    a.user_id,
    jsonb_build_object(
        'user_id', u.user_id,
        'email', u.email,
        'first_name', u.first_name,
        'last_name', u.last_name,
        'full_name', concat(u.first_name, ' ', u.last_name),
        'profile_picture_url', users.profile_picture_url(u.user_id)
    ) as owner,
    a.created_at,
    a.updated_at
from applications.application a
join
    users.user u
on
    a.user_id = u.user_id
where
    u.organization_id = auth.current_user_organization_id()
and (
    (
        auth.current_user_role() = 'org_client' 
        and a.user_id = auth.current_user_id()
    )
    or auth.current_user_role() in ('org_admin', 'org_owner')
);

grant select on api.applications to authenticated;

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

begin;
-- Create a schema for forms
create schema if not exists forms;
grant usage on schema forms to authenticated;

create table if not exists forms.form (
    form_id bigint default utils.generate_random_id() not null primary key,
    created_by bigint references users.user(user_id) on delete set null,
    created_at timestamp with time zone default now() not null
);

create table if not exists forms.form_template (
    form_template_id bigint default utils.generate_random_id() not null primary key,
    organization_id bigint references organizations.organization(organization_id) on delete cascade,
    form_id bigint references forms.form(form_id) on delete cascade,
    template_name text not null,
    created_by bigint references users.user(user_id) on delete set null,
    created_at timestamp with time zone default now() not null
);

create or replace function forms.validate_create_form_template_input(
    _created_by bigint,
    _template_name text,
    _organization_id bigint
) returns text
    language plpgsql
    security definer
as
$$
begin
    if _created_by is null or _created_by <= 0 then
        return 'missing_created_by';
    end if;

    if _template_name is null or _template_name = '' then
        return 'missing_template_name';
    end if;

    if _organization_id is null or _organization_id <= 0 then
        return 'missing_organization_id';
    end if;

    if not exists (
        select 
            1
        from 
            users.user u
        where 
            u.user_id = _created_by
        and 
            u.organization_id = _organization_id
    ) then
        return 'user_not_found';
    end if;

    return null;
end;
$$;

create or replace function forms.create_form_template(
    _created_by bigint,
    _template_name text,
    _organization_id bigint,
    out validation_failure_message text,
    out created_form forms.form,
    out created_form_template forms.form_template
) returns record
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := forms.validate_create_form_template_input(_created_by, _template_name, _organization_id);
    if validation_failure_message is not null then
        return;
    end if;

    -- Create the form
    insert into 
        forms.form (created_by) 
    values 
        (_created_by)
    returning * into created_form;

    -- Create the form template
    insert into 
        forms.form_template (form_id, template_name, organization_id, created_by)
    values
        (created_form.form_id, _template_name, _organization_id, _created_by)
    returning * into created_form_template;

    return;
end;
$$;

create or replace function api.create_form_template(template_name text) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_id bigint := auth.current_user_id();
    _current_user_role users.user_role := auth.current_user_role();
    _current_user_org_id bigint := auth.current_user_organization_id();
    _create_form_result record;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Creation Failed'
            using
                detail = 'You are not authorized to create a form template',
                hint = 'unauthorized';
    end if;

    _create_form_result := forms.create_form_template(_current_user_id, template_name, _current_user_org_id);
    if _create_form_result.validation_failure_message is not null then
        raise exception 'Form Template Creation Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_form_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'form_template', _create_form_result.created_form_template
    );
end;
$$;

grant execute on function api.create_form_template(text) to authenticated;

create or replace function forms.validate_update_form_template_input(
    _form_template_id bigint,
    _template_name text
) returns text
    language plpgsql
    security definer
as
$$
begin
    if _form_template_id is null or _form_template_id <= 0 then
        return 'missing_form_template_id';
    end if;

    if _template_name is null or _template_name = '' then
        return 'missing_template_name';
    end if;

    if not exists (
        select 
            1
        from 
            forms.form_template ft
        where 
            ft.form_template_id = _form_template_id
    ) then
        return 'form_template_not_found';
    end if;

    return null;
end;
$$;

create or replace function forms.update_form_template(
    _form_template_id bigint,
    _template_name text,
    out validation_failure_message text,
    out updated_form_template forms.form_template
) returns record
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := forms.validate_update_form_template_input(_form_template_id, _template_name);
    if validation_failure_message is not null then
        return;
    end if;

    update 
        forms.form_template
    set 
        template_name = _template_name
    where 
        form_template_id = _form_template_id
    and
        organization_id = auth.current_user_organization_id()
    returning * into updated_form_template;

    return;
end;
$$;

create or replace function api.update_form_template(form_template_id bigint, template_name text) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _update_form_template_result record;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Update Failed'
            using
                detail = 'You are not authorized to update this form template',
                hint = 'unauthorized';
    end if;

    _update_form_template_result := forms.update_form_template(form_template_id, template_name);
    if _update_form_template_result.validation_failure_message is not null then
        raise exception 'Form Template Update Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _update_form_template_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'form_template', _update_form_template_result.updated_form_template
    );
end;
$$;

grant execute on function api.update_form_template(bigint, text) to authenticated;

create or replace function api.delete_form_template(form_template_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Deletion Failed'
            using
                detail = 'You are not authorized to delete this form template',
                hint = 'unauthorized';
    end if;

    delete from
        forms.form_template ft
    where
        ft.form_template_id = $1
    and
        ft.organization_id = auth.current_user_organization_id();

    return jsonb_build_object('success', true);
end;
$$;

grant execute on function api.delete_form_template(bigint) to authenticated;

create or replace view api.form_templates as
select
    ft.form_template_id,
    ft.organization_id,
    ft.form_id,
    ft.template_name,
    ft.created_by,
    ft.created_at
from forms.form_template ft
where ft.organization_id = auth.current_user_organization_id();

grant select on api.form_templates to authenticated;

-- Form Category
create table if not exists forms.form_category (
    form_category_id bigint default utils.generate_random_id() not null primary key,
    form_id bigint references forms.form(form_id) on delete cascade,
    category_name text not null,
    category_position int not null check (category_position > 0),
    created_at timestamp with time zone default now() not null,
    unique (form_id, category_position)
);

create or replace function forms.validate_create_form_category_input(
    _form_id bigint,
    _category_name text,
    _category_position int
) returns text
    language plpgsql
    security definer
as
$$
begin
    if _form_id is null or _form_id <= 0 then
        return 'missing_form_id';
    end if;

    if _category_name is null or _category_name = '' then
        return 'missing_category_name';
    end if;

    if _category_position is null or _category_position < 1 then
        return 'missing_category_position';
    end if;

    if not exists (
        select
            1
        from
            forms.form f
        join
            forms.form_template ft
        on
            f.form_id = ft.form_id
        where
            f.form_id = _form_id
        and
            ft.organization_id = auth.current_user_organization_id()
    ) then
        return 'form_not_found';
    end if;

    if exists (
        select
            1
        from
            forms.form_category fc
        where
            fc.form_id = _form_id and fc.category_position = _category_position
    ) then
        return 'category_position_already_exists';
    end if;

    return null;
end;
$$;

create or replace function forms.create_form_category(
    _form_id bigint,
    _category_name text,
    _category_position int,
    out validation_failure_message text,
    out created_form_category forms.form_category
) returns record
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := forms.validate_create_form_category_input(_form_id, _category_name, _category_position);
    if validation_failure_message is not null then
        return;
    end if;

    insert into
        forms.form_category (form_id, category_name, category_position)
    values
        (_form_id, _category_name, _category_position)
    returning * into created_form_category;

    return;
end;
$$;

create or replace function forms.form_id_by_form_template_id(_form_template_id bigint) returns bigint
    language sql
    stable
as
$$
select form_id from forms.form_template where form_template_id = _form_template_id;
$$;

create or replace function api.create_form_template_category(form_template_id bigint, category_name text, category_position int) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _form_id bigint := forms.form_id_by_form_template_id(form_template_id);
    _create_form_category_result record;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Category Creation Failed'
            using
                detail = 'You are not authorized to create a form category',
                hint = 'unauthorized';
    end if;

    _create_form_category_result := forms.create_form_category(_form_id, category_name, category_position);
    if _create_form_category_result.validation_failure_message is not null then
        raise exception 'Form Category Creation Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_form_category_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'form_category', _create_form_category_result.created_form_category
    );
end;
$$;

grant execute on function api.create_form_template_category(bigint, text, int) to authenticated;

create or replace function forms.validate_update_form_categories_input(_form_categories jsonb[]) returns text
    language plpgsql
    security definer
as
$$
declare
    _required_fields text[] := array['form_category_id', 'form_id', 'category_name', 'category_position'];
    _distinct_form_ids bigint[];
    _form_category jsonb;
    _field_name text;
    _form_id bigint;
begin
    if array_length(_form_categories, 1) is null then
        return 'missing_form_categories';
    end if;

    -- Validate all form_ids are the same
    select array_agg(distinct (c->>'form_id')::bigint)
    into _distinct_form_ids
    from unnest(_form_categories) as c;

    -- Check if we have exactly one form_id that's not null
    if array_length(_distinct_form_ids, 1) != 1 or _distinct_form_ids[1] is null then
        return 'distinct_form_id_not_found';
    end if;

    _form_id := _distinct_form_ids[1];

    -- Validate all required fields are present
    foreach _form_category in array _form_categories loop
        foreach _field_name in array _required_fields loop
            if not _form_category ? _field_name then
                return 'missing_' || _field_name;
            end if;
        end loop;

        -- Validate category_position positive integer
        if (_form_category->>'category_position')::int is null or (_form_category->>'category_position')::int < 1 then
            return 'invalid_category_position';
        end if;

        -- Validate category_name is not empty
        if trim(_form_category->>'category_name') = '' then
            return 'invalid_category_name';
        end if;
    end loop;

    -- Validate category_position is unique
    if exists (
        select 1
        from unnest(_form_categories) c1
        join unnest(_form_categories) c2 on 
            (c1->>'category_position')::int = (c2->>'category_position')::int
            and c1->>'form_category_id' != c2->>'form_category_id'
    ) then
        return 'non_unique_category_position';
    end if;

    -- Validate form_category_ids exist and belong to the correct form
    if exists (
        select 1
        from unnest(_form_categories) c
        where not exists (
            select 1 
            from forms.form_category fc
            where fc.form_category_id = (c->>'form_category_id')::bigint
            and fc.form_id = _form_id
        )
    ) then
        return 'invalid_form_category_id';
    end if;

    return null;
end;
$$;

create or replace function api.update_form_template_categories(form_categories jsonb[]) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _update_form_categories_result record;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Categories Update Failed'
            using
                detail = 'You are not authorized to update the form template categories',
                hint = 'unauthorized';
    end if;

    _update_form_categories_result := forms.update_form_categories(form_categories);
    if _update_form_categories_result.validation_failure_message is not null then
        raise exception 'Form Template Categories Update Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _update_form_categories_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'form_categories', coalesce(
            to_jsonb(_update_form_categories_result.updated_form_categories),
            '[]'::jsonb
        )
    );
end;
$$;

grant execute on function api.update_form_template_categories(jsonb[]) to authenticated;

create or replace function api.delete_form_template_category(form_category_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _target_org_id bigint := auth.current_user_organization_id();
    _target_form_id bigint := forms.form_id_by_form_category_id(form_category_id);
    _target_form_category_position int := forms.form_category_position_by_form_category_id(form_category_id);
    _remaining_form_categories jsonb;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Category Deletion Failed'
            using
                detail = 'You are not authorized to delete this form template category',
                hint = 'unauthorized';
    end if;

    delete from forms.form_category fc
    using forms.form f,
          forms.form_template ft
    where fc.form_category_id = $1
    and f.form_id = ft.form_id
    and ft.organization_id = _target_org_id;

    if not found then
        raise exception 'Form Template Category Deletion Failed'
            using
                detail = 'Form Template Category not found',
                hint = 'template_category_not_found';
    end if;

    -- Reorder the categories
    update forms.form_category fc
    set category_position = fc.category_position - 1
    where fc.form_id = _target_form_id
    and fc.category_position > _target_form_category_position;

    -- Return remaining form categories
    select json_agg(fc) into _remaining_form_categories
    from forms.form_category fc
    where fc.form_id = _target_form_id;

    return jsonb_build_object(
        'form_categories', _remaining_form_categories
    );
end;
$$;

grant execute on function api.delete_form_template_category(bigint) to authenticated;

create or replace function forms.form_category_position_by_form_category_id(_form_category_id bigint) returns int
    language sql
    stable
as
$$
select category_position from forms.form_category where form_category_id = _form_category_id;
$$;

create or replace function forms.form_id_by_form_category_id(_form_category_id bigint) returns bigint
    language sql
    stable
as
$$
select form_id from forms.form_category where form_category_id = _form_category_id;
$$;

create table if not exists forms.form_section (
    form_section_id bigint default utils.generate_random_id() not null primary key,
    form_category_id bigint references forms.form_category(form_category_id) on delete cascade,
    section_name text not null,
    section_position int not null check (section_position > 0),
    created_at timestamp with time zone default now() not null,
    unique (form_category_id, section_position)
);

create or replace function forms.form_organization_id(_form_id bigint) returns bigint
    language sql
    stable
as
$$
    select organization_id
    from (
        select ft.organization_id
        from forms.form f
        join forms.form_template ft
        using (form_id)
        where f.form_id = _form_id
        
        union
        
        select af.organization_id
        from forms.form f
        join applications.application_form af
        using (form_id)
        where f.form_id = _form_id
    ) combined;
$$;

create or replace function forms.validate_create_form_section_input(
    _form_category_id bigint,
    _section_name text,
    _section_position int
) returns text
    language plpgsql
    security definer
as
$$
declare
    _target_org_id bigint := auth.current_user_organization_id();
begin
    if _form_category_id is null or _form_category_id <= 0 then
        return 'missing_form_category_id';
    end if;

    if _section_name is null or _section_name = '' then
        return 'missing_section_name';
    end if;

    if _section_position is null or _section_position < 1 then
        return 'missing_section_position';
    end if;

    if not exists (
        select 1
        from forms.form_category fc
        where fc.form_category_id = _form_category_id
        and forms.form_organization_id(fc.form_id) = _target_org_id
    ) then
        return 'form_category_not_found';
    end if;

    if exists (
        select 1
        from forms.form_section fs
        where fs.form_category_id = _form_category_id
        and fs.section_position = _section_position
    ) then
        return 'section_position_already_exists';
    end if;

    return null;
end;
$$;

create or replace function forms.create_form_section(
    _form_category_id bigint,
    _section_name text,
    _section_position int,
    out validation_failure_message text,
    out created_form_section forms.form_section
) returns record
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := forms.validate_create_form_section_input(_form_category_id, _section_name, _section_position);
    if validation_failure_message is not null then
        return;
    end if;

    insert into 
        forms.form_section (form_category_id, section_name, section_position)
    values
        (_form_category_id, _section_name, _section_position)
    returning * into created_form_section;

    return;
end;
$$;

create or replace function api.create_form_section(form_category_id bigint, section_name text, section_position int) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _create_form_section_result record;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Section Creation Failed'
            using
                detail = 'You are not authorized to create a form section',
                hint = 'unauthorized';
    end if;

    _create_form_section_result := forms.create_form_section(form_category_id, section_name, section_position);
    if _create_form_section_result.validation_failure_message is not null then
        raise exception 'Form Section Creation Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_form_section_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'form_section', _create_form_section_result.created_form_section
    );
end;
$$;

grant execute on function api.create_form_section(bigint, text, int) to authenticated;

create or replace function forms.validate_update_form_sections_input(_form_sections jsonb[]) returns text
    language plpgsql
    security definer
as
$$
declare
    _required_fields text[] := array['form_section_id', 'form_category_id', 'section_name', 'section_position'];
    _distinct_form_category_ids bigint[];
    _form_section jsonb;
    _field_name text;
    _form_category_id bigint;
begin
    if array_length(_form_sections, 1) is null then
        return 'missing_form_sections';
    end if;

    -- Validate all form_category_ids are the same
    select array_agg(distinct (c->>'form_category_id')::bigint)
    into _distinct_form_category_ids
    from unnest(_form_sections) as c;

    -- Check if we have exactly one form_category_id that's not null
    if array_length(_distinct_form_category_ids, 1) != 1 or _distinct_form_category_ids[1] is null then
        return 'distinct_form_category_id_not_found';
    end if;

    _form_category_id := _distinct_form_category_ids[1];

    -- Validate all required fields are present
    foreach _form_section in array _form_sections loop
        foreach _field_name in array _required_fields loop
            if not _form_section ? _field_name then
                return 'missing_' || _field_name;
            end if;
        end loop;

        -- Validate section_position positive integer
        if (_form_section->>'section_position')::int is null or (_form_section->>'section_position')::int < 1 then
            return 'invalid_section_position';
        end if;

        -- Validate section_name is not empty
        if trim(_form_section->>'section_name') = '' then
            return 'invalid_section_name';
        end if;
    end loop;

    -- Validate section_position is unique
    if exists (
        select 1
        from unnest(_form_sections) c1
        join unnest(_form_sections) c2 on 
            (c1->>'section_position')::int = (c2->>'section_position')::int
            and c1->>'form_section_id' != c2->>'form_section_id'
    ) then
        return 'non_unique_section_position';
    end if;

    -- Validate form_section_ids exist and belong to the correct form_category
    if exists (
        select 1
        from unnest(_form_sections) c
        where not exists (
            select 1 from forms.form_section fs where fs.form_section_id = (c->>'form_section_id')::bigint and fs.form_category_id = _form_category_id
        )
    ) then
        return 'invalid_form_section_id';
    end if;

    return null;
end;
$$;

create or replace function forms.update_form_sections(
    form_sections jsonb[],
    out validation_failure_message text,
    out updated_form_sections forms.form_section[]
) returns record
    language plpgsql
    security definer
as $$
declare
    _form_category_id bigint;
    _form_id bigint;
begin
    validation_failure_message := forms.validate_update_form_sections_input(form_sections);
    if validation_failure_message is not null then
        return;
    end if;

    select (form_sections[1]->>'form_category_id')::bigint into _form_category_id;
    select forms.form_id_by_form_category_id(_form_category_id) into _form_id;

    create temp table temp_sections (
        form_section_id bigint,
        section_name text,
        section_position int
    ) on commit drop;

    insert into temp_sections (
        form_section_id,
        section_name,
        section_position
    )

    select 
        (c->>'form_section_id')::bigint,
        c->>'section_name',
        (c->>'section_position')::int
    from unnest(form_sections) as c;

    update forms.form_section fs
    set
        section_name = ts.section_name,
        section_position = ts.section_position
    from temp_sections ts
    where fs.form_section_id = ts.form_section_id
    and fs.form_category_id = _form_category_id;

    -- Return ALL sections for the form
    select array_agg(fs.* order by fc.category_position, fs.section_position)
    into updated_form_sections
    from forms.form_section fs
    join forms.form_category fc on fc.form_category_id = fs.form_category_id
    where fc.form_id = _form_id;

    drop table if exists temp_sections;
end;
$$;

create or replace function api.update_form_template_sections(form_sections jsonb[]) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _update_form_sections_result record;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Sections Update Failed'
            using
                detail = 'You are not authorized to update the form template sections',
                hint = 'unauthorized';
    end if;

    _update_form_sections_result := forms.update_form_sections(form_sections);
    if _update_form_sections_result.validation_failure_message is not null then
        raise exception 'Form Template Sections Update Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _update_form_sections_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'form_sections', coalesce(
            to_jsonb(_update_form_sections_result.updated_form_sections),
            '[]'::jsonb
        )
    );
end;
$$;

grant execute on function api.update_form_template_sections(jsonb[]) to authenticated;

create or replace function forms.form_section_position(_form_section_id bigint) returns int
    language sql
    stable
as
$$
    select section_position
    from forms.form_section
    where form_section_id = _form_section_id;
$$;

create or replace function forms.form_category_id_by_form_section_id(_form_section_id bigint) returns bigint
    language sql
    stable
as
$$
select form_category_id from forms.form_section where form_section_id = _form_section_id;
$$;

create or replace function api.delete_form_template_section(form_section_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _target_org_id bigint := auth.current_user_organization_id();
    _target_form_section_position int := forms.form_section_position_by_form_section_id(form_section_id);
    _target_form_category_id bigint := forms.form_category_id_by_form_section_id(form_section_id);
    _target_form_id bigint := forms.form_id_by_form_category_id(_target_form_category_id);
    _remaining_form_sections jsonb;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Section Deletion Failed'
            using
                detail = 'You are not authorized to delete this form template section',
                hint = 'unauthorized';
    end if;

    delete from forms.form_section fs
    using forms.form_category fc,
          forms.form f,
          forms.form_template ft
    where fs.form_section_id = $1
    and fc.form_category_id = fs.form_category_id
    and f.form_id = fc.form_id
    and ft.form_id = f.form_id
    and ft.organization_id = _target_org_id;

    if not found then
        raise exception 'Form Template Section Deletion Failed'
            using
                detail = 'Form Template Section not found',
                hint = 'section_not_found';
    end if;

    -- Reorder the sections in the form_category
    update forms.form_section fs
    set section_position = fs.section_position - 1
    where fs.form_category_id = _target_form_category_id
    and fs.section_position > _target_form_section_position;

    -- Return remaining form sections
    select json_agg(fs order by fc.category_position, fs.section_position) into _remaining_form_sections
    from forms.form_section fs
    join forms.form_category fc on fc.form_category_id = fs.form_category_id
    join forms.form f on fc.form_id = f.form_id
    join forms.form_template ft on f.form_id = ft.form_id
    where fc.form_id = _target_form_id
    and ft.organization_id = _target_org_id;

    return jsonb_build_object('form_sections', _remaining_form_sections);
end;
$$;

grant execute on function api.delete_form_template_section(bigint) to authenticated;

-- Form Question Set
do $$ 
begin
    if not exists (select 1 from pg_type where typname = 'form_question_set_type') then
        create domain forms.form_question_set_type as text
        check (
            value in ('static', 'repeatable', 'conditional')
        );
    end if;
end $$;

create table if not exists forms.form_question_set (
    form_question_set_id bigint default utils.generate_random_id() not null primary key,
    form_section_id bigint references forms.form_section(form_section_id) on delete cascade,
    form_question_set_type forms.form_question_set_type not null,
    form_question_set_position int not null check (form_question_set_position > 0),
    depends_on_option_id bigint null references forms.form_question_option(form_question_option_id) on delete cascade deferrable initially deferred,
    parent_form_question_set_id bigint references forms.form_question_set(form_question_set_id) on delete cascade deferrable initially deferred,
    created_at timestamp with time zone default now() not null,
    unique (parent_form_question_set_id, form_question_set_position)
);

-- Create a partial unique index for root-level question sets
create unique index form_question_set_section_position_unique 
on forms.form_question_set (form_section_id, form_question_set_position)
where parent_form_question_set_id is null;

do $$
begin
    if not exists (select 1 from pg_type where typname = 'form_question_type') then
        create domain forms.form_question_type as text
        check (
            value in ('text', 'textarea', 'select', 'date', 'radio', 'checkbox', 'file')
        );
    end if;
end $$;

create table if not exists forms.form_question (
    form_question_id bigint default utils.generate_random_id() not null primary key,
    form_question_set_id bigint references forms.form_question_set(form_question_set_id) on delete cascade,
    form_question_prompt text not null,
    form_question_type forms.form_question_type not null,
    form_question_position int not null check (form_question_position > 0),
    created_at timestamp with time zone default now() not null,
    unique (form_question_set_id, form_question_position)
);

do $$ 
begin
    if not exists (select 1 from pg_type where typname = 'form_question_display_type') then
        create domain forms.form_question_display_type as text
        check (
            value in ('inline', 'block')
        );
    end if;
end $$;

create table if not exists forms.form_question_settings (
    form_question_settings_id bigint default utils.generate_random_id() not null primary key,
    form_question_id bigint references forms.form_question(form_question_id) on delete cascade,
    helper_text text,
    is_required boolean default false not null,
    placeholder_text text,
    minimum_length int,
    maximum_length int,
    minimum_date date,
    maximum_date date,
    display_type forms.form_question_display_type,
    created_at timestamp with time zone default now() not null,
    unique (form_question_id)
);

create or replace function forms.form_section_question_sets(_form_section_id bigint) returns forms.form_question_set[]
    language sql
    stable
as
$$
    select array_agg(fqs order by fqs.form_question_set_position)
    from forms.form_question_set fqs
    where fqs.form_section_id = _form_section_id;
$$;

create or replace function forms.form_question_settings(_form_question_id bigint) returns forms.form_question_settings
    language sql
    stable
as
$$
    select *
    from forms.form_question_settings
    where form_question_id = _form_question_id;
$$;

create or replace function forms.form_id_by_form_section_id(_form_section_id bigint) returns bigint
    language sql
    stable
as
$$
    select fc.form_id 
    from forms.form_section fs
    join forms.form_category fc on fs.form_category_id = fc.form_category_id
    where fs.form_section_id = _form_section_id;
$$;

create or replace function forms.validate_create_form_question_input(
    _form_question_set_id bigint,
    _form_question_prompt text,
    _form_question_type forms.form_question_type,
    _form_question_position int
) returns text
    language plpgsql
    security definer
as
$$
declare
    _target_org_id bigint := auth.current_user_organization_id();
begin
    if _form_question_set_id is null or _form_question_set_id <= 0 then
        return 'missing_form_question_set_id';
    end if;

    if _form_question_prompt is null or _form_question_prompt = '' then
        return 'missing_form_question_prompt';
    end if;

    if _form_question_type is null then
        return 'missing_form_question_type';
    end if;

    if _form_question_position is null or _form_question_position < 1 then
        return 'missing_form_question_position';
    end if;

    if not exists (
        select 1
        from forms.form_question_set fqs
        join forms.form_section fs on fqs.form_section_id = fs.form_section_id
        join forms.form_category fc on fs.form_category_id = fc.form_category_id
        where fqs.form_question_set_id = _form_question_set_id
        and forms.form_organization_id(fc.form_id) = _target_org_id
    ) then
        return 'form_question_set_not_found';
    end if;

    return null;
end;
$$;

create or replace function forms.create_form_question(
    _form_question_set_id bigint,
    _form_question_prompt text,
    _form_question_type forms.form_question_type,
    _form_question_position int,
    out validation_failure_message text,
    out created_form_question forms.form_question
) returns record
    language plpgsql
    security definer
as
$$
declare
    _r record;
begin
    validation_failure_message := forms.validate_create_form_question_input(_form_question_set_id, _form_question_prompt, _form_question_type, _form_question_position);
    if validation_failure_message is not null then
        return;
    end if;

    -- Create temporary table for current positions
    create temp table temp_positions (
        form_question_id bigint,
        current_position int,
        new_position int
    ) on commit drop;

    -- Insert current records that need position updates
    insert into temp_positions (form_question_id, current_position, new_position)
    select
        form_question_id,
        form_question_position,
        form_question_position + 1
    from forms.form_question
    where form_question_set_id = _form_question_set_id
    and form_question_position >= _form_question_position
    order by form_question_position desc;

    -- Update existing positions one by one, from highest to lowest
    for _r in (select * from temp_positions order by current_position desc) loop
        update forms.form_question
        set form_question_position = _r.new_position
        where form_question_id = _r.form_question_id;
    end loop;

    -- Insert the new question
    insert into forms.form_question (
        form_question_set_id,
        form_question_prompt,
        form_question_type,
        form_question_position
    ) values (
        _form_question_set_id,
        _form_question_prompt,
        _form_question_type,
        _form_question_position
    ) returning * into created_form_question;

    -- Cleanup
    drop table if exists temp_positions;

    return;
end;
$$;

create or replace function forms.validate_create_form_question_settings_input(
    _form_question_settings jsonb
) returns text
    language plpgsql
    security definer
as
$$
declare
    _form_question_id bigint := (_form_question_settings->>'form_question_id')::bigint;
    _is_required boolean := (_form_question_settings->>'is_required')::boolean;
begin
    if _form_question_id is null or _form_question_id <= 0 then
        return 'missing_form_question_id';
    end if;

    if _is_required is null then
        return 'missing_is_required';
    end if;

    return null;
end;
$$;

create or replace function forms.create_form_question_settings(
    _form_question_settings jsonb,
    out validation_failure_message text,
    out created_form_question_settings forms.form_question_settings
) returns record
    language plpgsql
    security definer
as
$$
declare
    _form_question_id bigint := (_form_question_settings->>'form_question_id')::bigint;
    _helper_text text := nullif(_form_question_settings->>'helper_text', '')::text;
    _is_required boolean := (_form_question_settings->>'is_required')::boolean;
    _placeholder_text text := nullif(_form_question_settings->>'placeholder_text', '')::text;
    _minimum_length int := nullif(_form_question_settings->>'minimum_length', '')::int;
    _maximum_length int := nullif(_form_question_settings->>'maximum_length', '')::int;
    _minimum_date date := nullif(_form_question_settings->>'minimum_date', '')::date;
    _maximum_date date := nullif(_form_question_settings->>'maximum_date', '')::date;
    _display_type forms.form_question_display_type := nullif(_form_question_settings->>'display_type', '')::forms.form_question_display_type;
begin
    validation_failure_message := forms.validate_create_form_question_settings_input(_form_question_settings);
    if validation_failure_message is not null then
        return;
    end if;

    insert into forms.form_question_settings (
        form_question_id,
        helper_text,
        is_required,
        placeholder_text,
        minimum_length,
        maximum_length,
        minimum_date,
        maximum_date,
        display_type
    ) values (
        _form_question_id, 
        _helper_text, 
        _is_required,
        _placeholder_text,
        _minimum_length,
        _maximum_length,
        _minimum_date,
        _maximum_date,
        _display_type
    ) returning * into created_form_question_settings;

    return;
end;
$$;

create or replace function forms.validate_create_form_question_set_input(
    _form_section_id bigint,
    _form_question_set_type forms.form_question_set_type,
    _form_question_set_position int,
    _depends_on_option_id bigint default null,
    _parent_form_question_set_id bigint default null
) returns text
    language plpgsql
    security definer
as
$$
begin
    if _form_section_id is null or _form_section_id <= 0 then
        return 'missing_form_section_id';
    end if;

    if _form_question_set_type is null then
        return 'missing_form_question_set_type';
    end if;

    if _form_question_set_position is null or _form_question_set_position < 1 then
        return 'missing_form_question_set_position';
    end if;

    if _depends_on_option_id is not null then
        return null;
    end if;

    if _parent_form_question_set_id is not null then
        if not exists (
            select 1
            from forms.form_question_set fqs
            where fqs.form_question_set_id = _parent_form_question_set_id
        ) then
            return 'parent_form_question_set_not_found';
        end if;
    end if;

    return null;
end;
$$;

create or replace function forms.create_form_question_set(
    _form_section_id bigint,
    _form_question_set_type forms.form_question_set_type,
    _form_question_set_position int,
    _depends_on_option_id bigint default null,
    _parent_form_question_set_id bigint default null,
    out validation_failure_message text,
    out created_form_question_set forms.form_question_set
) returns record
    language plpgsql
    security definer
as
$$
declare
    _r record;
begin
    validation_failure_message := forms.validate_create_form_question_set_input(_form_section_id, _form_question_set_type, _form_question_set_position, _depends_on_option_id, _parent_form_question_set_id);
    if validation_failure_message is not null then
        return;
    end if;

    -- Create temporary table for current positions
    create temp table temp_positions (
        form_question_set_id bigint,
        current_position int,
        new_position int
    ) on commit drop;

    -- Insert current records that need position updates
    if _parent_form_question_set_id is not null then
        -- For nested question sets
        insert into temp_positions (form_question_set_id, current_position, new_position)
        select
            form_question_set_id,
            form_question_set_position,
            form_question_set_position + 1
        from forms.form_question_set
        where parent_form_question_set_id = _parent_form_question_set_id
        and form_question_set_position >= _form_question_set_position
        order by form_question_set_position desc;
    else
        -- For root level question sets
        insert into temp_positions (form_question_set_id, current_position, new_position)
        select
            form_question_set_id,
            form_question_set_position,
            form_question_set_position + 1
        from forms.form_question_set
        where form_section_id = _form_section_id
        and parent_form_question_set_id is null
        and form_question_set_position >= _form_question_set_position
        order by form_question_set_position desc;
    end if;

    -- Update existing positions one by one, from highest to lowest
    for _r in (select * from temp_positions order by current_position desc) loop
        update forms.form_question_set
        set form_question_set_position = _r.new_position
        where form_question_set_id = _r.form_question_set_id;
    end loop;

    -- Insert the new question set
    insert into forms.form_question_set (
        form_section_id, 
        form_question_set_type, 
        form_question_set_position, 
        depends_on_option_id, 
        parent_form_question_set_id
    )
    values (
        _form_section_id, 
        _form_question_set_type, 
        _form_question_set_position, 
        _depends_on_option_id, 
        _parent_form_question_set_id
    ) returning * into created_form_question_set;

    -- Cleanup
    drop table if exists temp_positions;

    return;
end;
$$;

create or replace function forms.form_section_id_by_form_question_set_id(_form_question_set_id bigint) returns bigint
    language sql
    stable
as
$$
    select
        form_section_id
    from
        forms.form_question_set
    where
        form_question_set_id = _form_question_set_id;
$$;

create or replace function forms.parent_form_question_set_id_by_form_question_set_id(_form_question_set_id bigint) returns bigint
    language sql
    stable
as
$$
    select 
        parent_form_question_set_id
    from 
        forms.form_question_set
    where 
        form_question_set_id = _form_question_set_id;
$$;

create or replace function forms.form_question_set_position(_form_question_set_id bigint) returns int
    language sql
    stable
as
$$
    select form_question_set_position
    from forms.form_question_set
    where form_question_set_id = _form_question_set_id;
$$;

create or replace function forms.delete_form_question_set(
    _form_question_set_id bigint,
    out validation_failure_message text
) returns text
    language plpgsql
    security definer
as
$$
declare
    _parent_form_question_set_id bigint := forms.parent_form_question_set_id_by_form_question_set_id(_form_question_set_id);
    _target_form_question_set_position int := forms.form_question_set_position(_form_question_set_id);
    _target_form_section_id bigint := forms.form_section_id_by_form_question_set_id(_form_question_set_id);
begin
    delete from forms.form_question_set fqs
    using forms.form_section fs
    where fqs.form_question_set_id = _form_question_set_id
    and fs.form_section_id = fqs.form_section_id;

    if not found then
        validation_failure_message := 'form_question_set_not_found';
        return;
    end if;

    -- Reorder the question sets
    if _parent_form_question_set_id is not null then
        -- For nested question sets, update positions within the parent
        update forms.form_question_set
        set form_question_set_position = form_question_set_position - 1
        where parent_form_question_set_id = _parent_form_question_set_id
        and form_question_set_position > _target_form_question_set_position;
    else
        -- For root level question sets, update positions within the section
        update forms.form_question_set
        set form_question_set_position = form_question_set_position - 1
        where form_section_id = _target_form_section_id
        and parent_form_question_set_id is null
        and form_question_set_position > _target_form_question_set_position;
    end if;

    return;
end;
$$;

create or replace function api.delete_form_template_question_set(form_question_set_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _target_org_id bigint := auth.current_user_organization_id();
    _target_form_section_id bigint := forms.form_section_id_by_form_question_set_id(form_question_set_id);
    _target_form_id bigint := forms.form_id_by_form_section_id(_target_form_section_id);
    _target_form_organization_id bigint := forms.form_organization_id(_target_form_id);
    _validation_failure_message text;
begin
    if _current_user_role not in ('org_admin', 'org_owner') 
        or _target_form_organization_id != _target_org_id
    then
        raise exception 'Form Template Question Set Deletion Failed'
            using
                detail = 'You are not authorized to delete this form template question set',
                hint = 'unauthorized';
    end if;

    _validation_failure_message := forms.delete_form_question_set(form_question_set_id);
    if _validation_failure_message is not null then
        raise exception 'Form Template Question Set Deletion Failed'
            using
                detail = 'Form Template Question Set not found',
                hint = 'form_question_set_not_found';
    end if;

    return jsonb_build_object(
        'form_question_sets', to_jsonb(forms.form_section_question_sets(_target_form_section_id))
    );
end;
$$;

grant execute on function api.delete_form_template_question_set(bigint) to authenticated;

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
begin
    _validation_failure_message := forms.delete_form_question_set(form_question_set_id);
    if _validation_failure_message is not null then
        raise exception 'Application Form Question Set Deletion Failed'
            using
                detail = 'Application Form Question Set not found',
                hint = 'form_question_set_not_found';
    end if;

    return jsonb_build_object(
        'form_question_sets', to_jsonb(forms.form_section_question_sets(_target_form_section_id)),
        'form_questions', forms.form_section_questions(_target_form_section_id, true)
    );
end;
$$;

grant execute on function api.delete_application_form_question_set(bigint) to authenticated;

create or replace function forms.form_id_by_form_question_set_id(_form_question_set_id bigint) returns bigint
    language sql
    stable
as
$$
    select fc.form_id
    from forms.form_question_set fqs
    join forms.form_section fs on fqs.form_section_id = fs.form_section_id
    join forms.form_category fc on fs.form_category_id = fc.form_category_id
    where fqs.form_question_set_id = _form_question_set_id;
$$;

create or replace function api.form_template_with_categories_and_sections(form_template_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _target_org_id bigint := auth.current_user_organization_id();
    _form_template forms.form_template;
    _form_categories forms.form_category[];
    _form_sections forms.form_section[];
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template With Categories And Sections Retrieval Failed'
            using
                detail = 'You are not authorized to retrieve the form template with categories and sections',
                hint = 'unauthorized';
    end if;

    select * 
    into _form_template
    from forms.form_template ft
    where ft.form_template_id = $1
    and ft.organization_id = _target_org_id;

    select array_agg(fc)
    into _form_categories
    from forms.form_category fc
    where fc.form_id = _form_template.form_id;

    select array_agg(fs)
    into _form_sections
    from forms.form_section fs
    where fs.form_category_id = any(
        select form_category_id 
        from forms.form_category 
        where form_id = _form_template.form_id
    );

    return jsonb_build_object(
        'form_template', _form_template,
        'form_categories', _form_categories,
        'form_sections', _form_sections
    );
end;
$$;

grant execute on function api.form_template_with_categories_and_sections(bigint) to authenticated;

create or replace function forms.form_id_by_form_question_id(_form_question_id bigint) returns bigint
    language sql
    stable
as
$$
    select fc.form_id
    from forms.form_question fq
    join forms.form_question_set fqs on fq.form_question_set_id = fqs.form_question_set_id
    join forms.form_section fs on fqs.form_section_id = fs.form_section_id
    join forms.form_category fc on fs.form_category_id = fc.form_category_id
    where fq.form_question_id = _form_question_id;
$$;

create or replace function forms.form_question_set_id_by_form_question_id(_form_question_id bigint) returns bigint
    language sql
    stable
as
$$
    select fq.form_question_set_id
    from forms.form_question fq
    where fq.form_question_id = _form_question_id;
$$;

create or replace function forms.form_question_position(_form_question_id bigint) returns int
    language sql
    stable
as
$$
    select fq.form_question_position
    from forms.form_question fq
    where fq.form_question_id = _form_question_id;
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
        order by fq.form_question_position
    ) into _form_section_questions
    from forms.form_question fq
    join forms.form_question_set fqs using (form_question_set_id)
    where fqs.form_section_id = _form_section_id;

    return coalesce(_form_section_questions, '[]'::jsonb);
end;
$$;

create or replace function api.delete_form_template_question(form_question_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _target_org_id bigint := auth.current_user_organization_id();
    _target_form_id bigint := forms.form_id_by_form_question_id(form_question_id);
    _target_form_organization_id bigint := forms.form_organization_id(_target_form_id);
    _target_form_question_set_id bigint := forms.form_question_set_id_by_form_question_id(form_question_id);
    _target_form_question_position int := forms.form_question_position(form_question_id);
    _target_form_section_id bigint := forms.form_section_id_by_form_question_set_id(_target_form_question_set_id);
    _r record;
begin
    if _current_user_role not in ('org_admin', 'org_owner') and _target_form_organization_id != _target_org_id then
        raise exception 'Form Template Question Deletion Failed'
            using
                detail = 'You are not authorized to delete this form template question',
                hint = 'unauthorized';
    end if;

    delete from forms.form_question fq
    where fq.form_question_id = $1;

    if not found then
        raise exception 'Form Template Question Deletion Failed'
            using
                detail = 'Form Template Question not found',
                hint = 'form_question_not_found';
    end if;

    for _r in (
        select fq.form_question_id
        from forms.form_question fq
        where form_question_set_id = _target_form_question_set_id
        and form_question_position > _target_form_question_position
        order by form_question_position
    )
    loop
        update forms.form_question fq
        set form_question_position = form_question_position - 1
        where fq.form_question_id = _r.form_question_id;
    end loop;

    return jsonb_build_object(
        'form_questions', forms.form_section_questions(_target_form_section_id)
    );
end;
$$;

grant execute on function api.delete_form_template_question(bigint) to authenticated;

create or replace function forms.validate_update_form_question_input(
    _form_question_id bigint,
    _form_question_prompt text,
    _form_question_type forms.form_question_type
) returns text
    language plpgsql
    security definer
as
$$
begin
    if _form_question_id is null or _form_question_id <= 0 then
        return 'missing_form_question_id';
    end if;

    if _form_question_prompt is null or _form_question_prompt = '' then
        return 'missing_form_question_prompt';
    end if;

    if _form_question_type is null then
        return 'missing_form_question_type';
    end if;

    if not exists (
        select 1
        from forms.form_question fq
        where fq.form_question_id = _form_question_id
    ) then
        return 'form_question_not_found';
    end if;

    return null;
end;
$$;

create or replace function forms.update_form_question(
    _updated_form_question jsonb,
    out validation_failure_message text,
    out updated_form_question forms.form_question
) returns record
    language plpgsql
    security definer
as
$$
declare
    _form_question_id bigint := (_updated_form_question->>'form_question_id')::bigint;
    _form_question_prompt text := _updated_form_question->>'form_question_prompt';
    _form_question_type forms.form_question_type := (_updated_form_question->>'form_question_type')::forms.form_question_type;
begin
    validation_failure_message := forms.validate_update_form_question_input(_form_question_id, _form_question_prompt, _form_question_type);
    if validation_failure_message is not null then
        return;
    end if;

    update forms.form_question
    set form_question_prompt = _form_question_prompt,
        form_question_type = _form_question_type
    where form_question_id = _form_question_id
    returning * into updated_form_question;
end;
$$;

create or replace function forms.validate_update_form_question_settings_input(
    _form_question_settings jsonb
) returns text
    language plpgsql
    security definer
as
$$
declare
    _form_question_id bigint := (_form_question_settings->>'form_question_id')::bigint;
    _is_required boolean := (_form_question_settings->>'is_required')::boolean;
begin
    if _is_required is null then
        return 'missing_is_required';
    end if;

    if not exists (
        select 1
        from forms.form_question fq
        where fq.form_question_id = _form_question_id
    ) then
        return 'form_question_not_found';
    end if;

    return null;
end;
$$;

create or replace function forms.update_form_question_settings(
    _form_question_settings jsonb,
    out validation_failure_message text,
    out updated_form_question_settings forms.form_question_settings
) returns record
    language plpgsql
    security definer
as
$$
declare
    _form_question_id bigint := (_form_question_settings->>'form_question_id')::bigint;
    _helper_text text := nullif(_form_question_settings->>'helper_text', '');
    _is_required boolean := (_form_question_settings->>'is_required')::boolean;
    _placeholder_text text := nullif(_form_question_settings->>'placeholder_text', '');
    _minimum_length int := nullif(_form_question_settings->>'minimum_length', '')::int;
    _maximum_length int := nullif(_form_question_settings->>'maximum_length', '')::int;
    _minimum_date date := nullif(_form_question_settings->>'minimum_date', '')::date;
    _maximum_date date := nullif(_form_question_settings->>'maximum_date', '')::date;
    _display_type forms.form_question_display_type := nullif(_form_question_settings->>'display_type', '')::forms.form_question_display_type;
begin
    validation_failure_message := forms.validate_update_form_question_settings_input(_form_question_settings);
    if validation_failure_message is not null then
        return;
    end if;

    update forms.form_question_settings
    set helper_text = _helper_text,
        is_required = _is_required,
        placeholder_text = _placeholder_text,
        minimum_length = _minimum_length,
        maximum_length = _maximum_length,
        minimum_date = _minimum_date,
        maximum_date = _maximum_date,
        display_type = _display_type
    where form_question_id = _form_question_id
    returning * into updated_form_question_settings;
end;
$$;

-- Form Question Options
create table if not exists forms.form_question_option (
    form_question_option_id bigint default utils.generate_random_id() not null primary key,
    form_question_id bigint references forms.form_question(form_question_id) on delete cascade,
    option_text text not null,
    option_position int not null check (option_position > 0),
    created_at timestamp with time zone default now() not null,
    unique (form_question_id, option_position),
    unique (form_question_id, form_question_option_id)
);

create or replace function forms.validate_create_form_question_options_input(
    _form_question_id bigint,
    _form_question_options jsonb
) returns text
    language plpgsql
    security definer
as
$$
declare
    _option jsonb;
    _seen_positions int[];
begin
    if _form_question_id is null or _form_question_id <= 0 then
        return 'missing_form_question_id';
    end if;
    
    if _form_question_options is null or jsonb_array_length(_form_question_options) = 0 then
        return 'missing_options';
    end if;
    
    if not exists (
        select 1
        from forms.form_question fq
        where fq.form_question_id = _form_question_id
    ) then
        return 'form_question_not_found';
    end if;

    _seen_positions := array[]::int[];
    
    for _option in select * from jsonb_array_elements(_form_question_options)
    loop
        if _option->>'option_text' is null or _option->>'option_text' = '' then
            return 'missing_option_text';
        end if;
        
        if (_option->>'option_position')::int is null or (_option->>'option_position')::int <= 0 then
            return 'missing_option_position';
        end if;
        
        -- Check for duplicate positions
        if (_option->>'option_position')::int = any(_seen_positions) then
            return 'duplicate_position';
        end if;
        
        _seen_positions := array_append(_seen_positions, (_option->>'option_position')::int);
    end loop;
    
    return null;
end;
$$;

create or replace function forms.create_form_question_options(
    _form_question_id bigint,
    _form_question_options jsonb,
    out validation_failure_message text,
    out created_form_question_options forms.form_question_option[]
) returns record
    language plpgsql
    security definer
as
$$
declare
    _option_json jsonb;
begin
    validation_failure_message := forms.validate_create_form_question_options_input(_form_question_id, _form_question_options);
    if validation_failure_message is not null then
        return;
    end if;

    -- Create temporary table to hold new positions
    create temporary table temp_positions (
        old_position int,
        new_position int
    ) on commit drop;

    -- Calculate new positions
    for _option_json in select * from jsonb_array_elements(_form_question_options)
    loop
        insert into temp_positions (old_position, new_position)
        select
            option_position,
            option_position + jsonb_array_length(_form_question_options)
        from forms.form_question_option
        where form_question_id = _form_question_id
        and option_position >= (_option_json->>'option_position')::int;
    end loop;

    -- Update existing positions
    update forms.form_question_option fqo
    set option_position = tp.new_position
    from temp_positions tp
    where fqo.form_question_id = _form_question_id
    and fqo.option_position = tp.old_position;

    -- Insert new options
    with inserted_options as (
        select
            (opt->>'option_text')::text as option_text,
            (opt->>'option_position')::int as option_position
        from jsonb_array_elements(_form_question_options) as opt
    ),
    new_options as (
        insert into forms.form_question_option (
            form_question_id,
            option_text,
            option_position
        )
        select
            _form_question_id,
            option_text,
            option_position
        from inserted_options
        returning *
    )
    select array_agg(new_options.* order by new_options.option_position)
    into created_form_question_options
    from new_options;

    return;
end;
$$;


create or replace function forms.form_question_options(_form_question_id bigint) returns setof forms.form_question_option
    language sql
    stable
as
$$
    select fqo.*
    from forms.form_question_option fqo
    where fqo.form_question_id = _form_question_id
    order by fqo.option_position;
$$;

create table if not exists forms.form_question_default_option (
    form_question_id bigint not null references forms.form_question(form_question_id) on delete cascade,
    form_question_option_id bigint not null references forms.form_question_option(form_question_option_id) on delete cascade,
    primary key (form_question_id, form_question_option_id),
    foreign key (form_question_id, form_question_option_id) 
        references forms.form_question_option(form_question_id, form_question_option_id)
);

create or replace function forms.form_question_default_options(
    _form_question_id bigint
) returns forms.form_question_default_option[]
    language sql
    stable
as
$$
    select array_agg(fqdo order by fqdo.form_question_option_id)
    from forms.form_question_default_option fqdo
    where fqdo.form_question_id = _form_question_id;
$$;

create or replace function forms.validate_create_form_question_default_option_input(
    _form_question_id bigint,
    _form_question_option_id bigint
) returns text
    language plpgsql
    security definer
as
$$
begin
    if _form_question_id is null or _form_question_id <= 0 then
        return 'missing_form_question_id';
    end if;

    if _form_question_option_id is null or _form_question_option_id <= 0 then
        return 'missing_form_question_option_id';
    end if;

    if not exists (
        select 1
        from forms.form_question_option fqo
        where fqo.form_question_option_id = _form_question_option_id
        and fqo.form_question_id = _form_question_id
    ) then
        return 'form_question_option_not_found';
    end if;

    if not exists (
        select 1
        from forms.form_question fq
        where fq.form_question_id = _form_question_id
    ) then
        return 'form_question_not_found';
    end if;

    if exists (
        select 1
        from forms.form_question_default_option fqdo
        where fqdo.form_question_id = _form_question_id
        and fqdo.form_question_option_id = _form_question_option_id
    ) then
        return 'form_question_default_option_already_exists';
    end if;

    return null;
end;
$$;

create or replace function forms.create_form_question_default_option(
    _form_question_id bigint,
    _form_question_option_id bigint,
    out validation_failure_message text,
    out created_form_question_default_option forms.form_question_default_option
) returns record
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := forms.validate_create_form_question_default_option_input(_form_question_id, _form_question_option_id);
    if validation_failure_message is not null then
        return;
    end if;

    insert into forms.form_question_default_option (form_question_id, form_question_option_id)
    values (_form_question_id, _form_question_option_id)
    returning * into created_form_question_default_option;
end;
$$;

create or replace function forms.validate_delete_form_question_default_option_input(
    _form_question_id bigint,
    _form_question_option_id bigint
) returns text
    language plpgsql
    security definer
as
$$
begin
    if _form_question_id is null or _form_question_id <= 0 then
        return 'missing_form_question_id';
    end if;

    if _form_question_option_id is null or _form_question_option_id <= 0 then
        return 'missing_form_question_option_id';
    end if;

    if not exists (
        select 1
        from forms.form_question_default_option fqdo
        where fqdo.form_question_id = _form_question_id
        and fqdo.form_question_option_id = _form_question_option_id
    ) then
        return 'form_question_default_option_not_found';
    end if;

    return null;
end;
$$;

create or replace function forms.delete_form_question_default_option(
    _form_question_id bigint,
    _form_question_option_id bigint,
    out validation_failure_message text
) returns text
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := forms.validate_delete_form_question_default_option_input(_form_question_id, _form_question_option_id);
    if validation_failure_message is not null then
        return;
    end if;

    delete from forms.form_question_default_option
    where form_question_id = _form_question_id
    and form_question_option_id = _form_question_option_id;

    return;
end;
$$;

create or replace function api.create_form_template_question(
    form_question_set_id bigint,
    form_question_prompt text,
    form_question_type forms.form_question_type,
    form_question_position int,
    form_question_settings jsonb default null,
    form_question_options jsonb default null
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _target_form_section_id bigint := forms.form_section_id_by_form_question_set_id(form_question_set_id);
    _create_form_question_result record;
    _create_form_question_settings_result record;
    _create_form_question_options_result record;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Question Creation Failed'
            using
                detail = 'You are not authorized to create a form template question',
                hint = 'unauthorized';
    end if;

    _create_form_question_result := forms.create_form_question(form_question_set_id, form_question_prompt, form_question_type, form_question_position);
    if _create_form_question_result.validation_failure_message is not null then
        raise exception 'Form Template Question Creation Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_form_question_result.validation_failure_message;
    end if;

    _create_form_question_settings_result := forms.create_form_question_settings(
        jsonb_build_object(
            'form_question_id', (_create_form_question_result.created_form_question).form_question_id
        ) || coalesce(form_question_settings, '{}'::jsonb)
    );

    if _create_form_question_settings_result.validation_failure_message is not null then
        raise exception 'Form Template Question Settings Creation Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_form_question_settings_result.validation_failure_message;
    end if;

    if form_question_options is not null then
        _create_form_question_options_result := forms.create_form_question_options(
            (_create_form_question_result.created_form_question).form_question_id,
            form_question_options
        );

        if _create_form_question_options_result.validation_failure_message is not null then
            raise exception 'Form Template Question Options Creation Failed'
                using
                    detail = 'Invalid Request Payload',
                    hint = _create_form_question_options_result.validation_failure_message;
        end if;
    end if;

    return jsonb_build_object(
        'form_questions', forms.form_section_questions(_target_form_section_id)
    );
end;
$$;

grant execute on function api.create_form_template_question(bigint, text, forms.form_question_type, int, jsonb, jsonb) to authenticated;

create or replace function api.form_template_section_question_sets_and_questions(form_section_id bigint) returns jsonb
    security definer
    language plpgsql
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Section Question Sets And Questions Retrieval Failed'
            using
                detail = 'You are not authorized to retrieve the form template section question sets and questions',
                hint = 'unauthorized';
    end if;

    return jsonb_build_object(
        'form_question_sets', to_jsonb(forms.form_section_question_sets($1)),
        'form_questions', forms.form_section_questions($1)
    );
end;
$$;

grant execute on function api.form_template_section_question_sets_and_questions(bigint) to authenticated;

create or replace function api.update_form_template_question(
    updated_form_question jsonb
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _form_question_id bigint := (updated_form_question->>'form_question_id')::bigint;
    _target_form_question_set_id bigint := (updated_form_question->>'form_question_set_id')::bigint;
    _target_form_id bigint := forms.form_id_by_form_question_id(_form_question_id);
    _current_user_role users.user_role := auth.current_user_role();
    _target_org_id bigint := auth.current_user_organization_id();
    _target_form_organization_id bigint := forms.form_organization_id(_target_form_id);
    _target_form_section_id bigint := forms.form_section_id_by_form_question_set_id(_target_form_question_set_id);
    _update_form_question_result record;
    _updated_form_section_questions jsonb;
begin
    if _current_user_role not in ('org_admin', 'org_owner') and _target_form_organization_id != _target_org_id then
        raise exception 'Form Template Question Update Failed'
            using
                detail = 'You are not authorized to update this form template question',
                hint = 'unauthorized';
    end if;

    _update_form_question_result := forms.update_form_question(updated_form_question);
    if _update_form_question_result.validation_failure_message is not null then
        raise exception 'Form Template Question Update Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _update_form_question_result.validation_failure_message;
    end if;

    _updated_form_section_questions := forms.form_section_questions(_target_form_section_id);

    return jsonb_build_object(
        'form_questions', _updated_form_section_questions
    );
end;
$$;

grant execute on function api.update_form_template_question(jsonb) to authenticated;

create or replace function api.update_form_template_question_settings(
    updated_form_question_settings jsonb
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _update_form_question_settings_result record;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Question Settings Update Failed'
            using
                detail = 'You are not authorized to update the form template question settings',
                hint = 'unauthorized';
    end if;

    _update_form_question_settings_result := forms.update_form_question_settings(updated_form_question_settings);

    if _update_form_question_settings_result.validation_failure_message is not null then
        raise exception 'Form Template Question Settings Update Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _update_form_question_settings_result.validation_failure_message;
    end if;

    return jsonb_build_object(
        'form_question_settings', to_jsonb(_update_form_question_settings_result.updated_form_question_settings)
    );
end;
$$;

grant execute on function api.update_form_template_question_settings(jsonb) to authenticated;

create or replace function forms.validate_create_form_question_option_input(
    _form_question_id bigint,
    _option_text text,
    _option_position int
) returns text
    language plpgsql
    security definer
as
$$
begin
    if _form_question_id is null or _form_question_id <= 0 then
        return 'missing_form_question_id';
    end if;

    if _option_text is null or _option_text = '' then
        return 'missing_option_text';
    end if;

    if _option_position is null or _option_position <= 0 then
        return 'missing_option_position';
    end if;

    if not exists (
        select 1
        from forms.form_question fq
        where fq.form_question_id = _form_question_id
    ) then
        return 'form_question_not_found';
    end if;

    return null;
end;
$$;

create or replace function forms.create_form_question_option(
    _form_question_option jsonb,
    out validation_failure_message text,
    out created_form_question_option forms.form_question_option
) returns record
    language plpgsql
    security definer
as
$$
declare
    _form_question_id bigint := (_form_question_option->>'form_question_id')::bigint;
    _option_text text := nullif(_form_question_option->>'option_text', '')::text;
    _option_position int := nullif(_form_question_option->>'option_position', '')::int;
begin
    validation_failure_message := forms.validate_create_form_question_option_input(_form_question_id, _option_text, _option_position);
    if validation_failure_message is not null then
        return;
    end if;

    -- Shift all options at or after the target position up by 1
    with options_to_update as (
        select form_question_option_id, option_position
        from forms.form_question_option
        where form_question_id = _form_question_id
        and option_position >= _option_position
    )
    update forms.form_question_option fqo
    set option_position = fqo.option_position + 1
    from options_to_update otu
    where fqo.form_question_option_id = otu.form_question_option_id;

    -- Insert the new option at the desired position
    insert into forms.form_question_option (
        form_question_id,
        option_text,
        option_position
    ) values (
        _form_question_id,
        _option_text,
        _option_position
    )
    returning * into created_form_question_option;
end;
$$;

create or replace function api.create_form_template_question_option(
    form_question_option jsonb
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _form_question_id bigint := (form_question_option->>'form_question_id')::bigint;
    _create_form_question_option_result record;
    _updated_form_question_options jsonb;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Question Option Creation Failed'
            using
                detail = 'You are not authorized to create a form template question option',
                hint = 'unauthorized';
    end if;

    _create_form_question_option_result := forms.create_form_question_option(form_question_option);

    if _create_form_question_option_result.validation_failure_message is not null then
        raise exception 'Form Template Question Option Creation Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_form_question_option_result.validation_failure_message;
    end if;

    -- Return the updated form question options for the question
    select jsonb_agg(fqo order by fqo.option_position)
    into _updated_form_question_options
    from forms.form_question_option fqo
    where fqo.form_question_id = _form_question_id;

    return jsonb_build_object(
        'form_question_options', _updated_form_question_options
    );
end;
$$;

grant execute on function api.create_form_template_question_option(jsonb) to authenticated;

create or replace function forms.validate_update_form_question_option_input(
    _form_question_option_id bigint,
    _option_text text,
    _option_position int
) returns text
    language plpgsql
    security definer
as
$$
begin
    if _form_question_option_id is null or _form_question_option_id <= 0 then
        return 'missing_form_question_option_id';
    end if;

    if _option_text is null or _option_text = '' then
        return 'missing_option_text';
    end if;

    if _option_position is null or _option_position <= 0 then
        return 'missing_option_position';
    end if;

    if not exists (
        select 1
        from forms.form_question_option fqo
        where fqo.form_question_option_id = _form_question_option_id
    ) then
        return 'form_question_option_not_found';
    end if;

    return null;
end;
$$;

create or replace function forms.update_form_question_option(
    _updated_form_question_option jsonb,
    out validation_failure_message text,
    out updated_form_question_option forms.form_question_option
) returns record
    language plpgsql
    security definer
as
$$
declare
    _form_question_option_id bigint := (_updated_form_question_option->>'form_question_option_id')::bigint;
    _option_text text := nullif(_updated_form_question_option->>'option_text', '')::text;
    _option_position int := nullif(_updated_form_question_option->>'option_position', '')::int;
    _original_position int;
    _form_question_id bigint;
    _r record;
begin
    validation_failure_message := forms.validate_update_form_question_option_input(_form_question_option_id, _option_text, _option_position);
    if validation_failure_message is not null then
        return;
    end if;

    -- Get the original position and form_question_id
    select option_position, form_question_id
    into _original_position, _form_question_id
    from forms.form_question_option
    where form_question_option_id = _form_question_option_id;

    -- Create temporary table for position updates
    create temp table temp_positions (
        form_question_option_id bigint,
        current_position int,
        new_position int
    ) on commit drop;

    if _option_position > _original_position then
        -- Moving down: shift intervening options up
        insert into temp_positions
        select
            form_question_option_id,
            option_position,
            option_position - 1
        from forms.form_question_option
        where form_question_id = _form_question_id
        and option_position > _original_position
        and option_position <= _option_position;
    elsif _option_position < _original_position then
        -- Moving up: shift intervening options down
        insert into temp_positions
        select
            form_question_option_id,
            option_position,
            option_position + 1
        from forms.form_question_option
        where form_question_id = _form_question_id
        and option_position >= _option_position
        and option_position < _original_position;
    end if;

    -- Update positions one by one to maintain uniqueness constraint
    for _r in (
        select * from temp_positions
        order by
            case when _option_position > _original_position then current_position
            else -current_position end
    ) loop
        update forms.form_question_option
        set option_position = _r.new_position
        where form_question_option_id = _r.form_question_option_id;
    end loop;

    -- Clean up the temporary table
    drop table temp_positions;

    -- Finally, update the target option
    update forms.form_question_option
    set
        option_text = _option_text,
        option_position = _option_position
    where form_question_option_id = _form_question_option_id
    returning * into updated_form_question_option;
end;
$$;

create or replace function api.update_form_template_question_option(
    updated_form_question_option jsonb
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _form_question_id bigint := nullif(updated_form_question_option->>'form_question_id', '')::bigint;
    _update_form_question_option_result record;
    _updated_form_question_options jsonb;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Question Option Update Failed'
            using
                detail = 'You are not authorized to update the form template question option',
                hint = 'unauthorized';
    end if;

    _update_form_question_option_result := forms.update_form_question_option(updated_form_question_option);

    if _update_form_question_option_result.validation_failure_message is not null then
        raise exception 'Form Template Question Option Update Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _update_form_question_option_result.validation_failure_message;
    end if;

    -- Return the updated form question options for the question
    select jsonb_agg(fqo order by fqo.option_position)
    into _updated_form_question_options
    from forms.form_question_option fqo
    where fqo.form_question_id = _form_question_id;

    return jsonb_build_object(
        'form_question_options', _updated_form_question_options
    );
end;
$$;

grant execute on function api.update_form_template_question_option(jsonb) to authenticated;

begin;

create or replace function api.delete_form_template_question_option(
    form_question_option_id bigint
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _target_form_question_id bigint;
    _target_form_question_option_position int;
    _remaining_form_question_options jsonb;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Question Option Deletion Failed'
            using
                detail = 'You are not authorized to delete the form template question option',
                hint = 'unauthorized';
    end if;

    select fqo.option_position, fqo.form_question_id
    into _target_form_question_option_position, _target_form_question_id
    from forms.form_question_option fqo
    where fqo.form_question_option_id = $1;

    -- Delete the form question option. shift all the options above it down
    delete from forms.form_question_option fqo
    where fqo.form_question_option_id = $1;

    -- Shift all the options above it down
    with options_to_update as (
        select fqo.form_question_option_id, fqo.option_position
        from forms.form_question_option fqo
        where fqo.form_question_id = _target_form_question_id
        and fqo.option_position > _target_form_question_option_position
    )
    update forms.form_question_option fqo
    set option_position = fqo.option_position - 1
    from options_to_update otu
    where fqo.form_question_option_id = otu.form_question_option_id;

    -- Return the remaining form question options for the question
    select jsonb_agg(fqo order by fqo.option_position)
    into _remaining_form_question_options
    from forms.form_question_option fqo
    where fqo.form_question_id = _target_form_question_id;

    return jsonb_build_object(
        'form_question_options', _remaining_form_question_options
    );
end;
$$;

grant execute on function api.delete_form_template_question_option(bigint) to authenticated;

create or replace function api.update_form_template_question_default_options(
    form_question_id bigint,
    updated_form_question_default_options jsonb
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _existing_form_question_default_options forms.form_question_default_option[] := forms.form_question_default_options(form_question_id);
    _input_form_question_default_options forms.form_question_default_option[];
    _form_question_option record;
    _create_form_question_default_option_result record;
    _delete_form_question_default_option_result text;
    _remaining_form_question_default_options forms.form_question_default_option[];
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Question Default Options Update Failed'
            using
                detail = 'You are not authorized to update the form template question default options',
                hint = 'unauthorized';
    end if;

    -- Parse input JSON array into form_question_default_option records
    select array_agg(row(
        form_question_id,
        (elem->>'form_question_option_id')::bigint
    )::forms.form_question_default_option)
    into _input_form_question_default_options
    from jsonb_array_elements(updated_form_question_default_options) as elem;

    -- Delete existing options that are not in the input array
    for _form_question_option in
        select e.form_question_option_id
        from unnest(_existing_form_question_default_options) e
        where not exists (
            select 1
            from unnest(_input_form_question_default_options) i
            where i.form_question_option_id = e.form_question_option_id
        )
    loop
        _delete_form_question_default_option_result := forms.delete_form_question_default_option(
            form_question_id,
            _form_question_option.form_question_option_id
        );

        if _delete_form_question_default_option_result is not null then
            raise exception 'Form Template Question Default Options Update Failed'
                using
                    detail = 'Failed to delete existing option',
                    hint = _delete_form_question_default_option_result;
        end if;
    end loop;

    -- Create new options that don't exist in the database
    for _form_question_option in
        select i.form_question_option_id
        from unnest(_input_form_question_default_options) i
        where not exists (
            select 1
            from unnest(_existing_form_question_default_options) e
            where e.form_question_option_id = i.form_question_option_id
        )
    loop
        _create_form_question_default_option_result := forms.create_form_question_default_option(
            form_question_id,
            _form_question_option.form_question_option_id
        );

        if _create_form_question_default_option_result.validation_failure_message is not null then
            raise exception 'Form Template Question Default Options Update Failed'
                using
                    detail = 'Failed to create new option',
                    hint = _create_form_question_default_option_result.validation_failure_message;
        end if;
    end loop;

    -- Return the updated form question default options for the question
    _remaining_form_question_default_options := forms.form_question_default_options(form_question_id);

    return jsonb_build_object(
        'form_question_default_options', to_jsonb(_remaining_form_question_default_options)
    );
end;
$$;

grant execute on function api.update_form_template_question_default_options(bigint, jsonb) to authenticated;

create or replace function api.create_form_template_question_set(
    form_section_id bigint,
    form_question_set_type forms.form_question_set_type,
    form_question_set_position int,
    depends_on_option_id bigint default null,
    parent_form_question_set_id bigint default null
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _create_form_question_set_result record;
    _create_form_question_result record;
    _create_form_question_settings_result record;
    _create_form_question_options_result record;
    _create_form_question_default_option_result record;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Template Question Set Creation Failed'
            using
                detail = 'You are not authorized to create a form template question set',
                hint = 'unauthorized';
    end if;

    _create_form_question_set_result := forms.create_form_question_set(form_section_id, form_question_set_type, form_question_set_position, depends_on_option_id, parent_form_question_set_id);
    if _create_form_question_set_result.validation_failure_message is not null then
        raise exception 'Form Template Question Set Creation Failed'
            using
                detail = 'Invalid Request Payload',
                hint = _create_form_question_set_result.validation_failure_message;
    end if;

    if (_create_form_question_set_result.created_form_question_set).form_question_set_type = 'conditional' then
        _create_form_question_result := forms.create_form_question(
            (_create_form_question_set_result.created_form_question_set).form_question_set_id,
            'Untitled Question',
            'radio',
            1
        );
        if _create_form_question_result.validation_failure_message is not null then
            raise exception 'Form Template Question Creation Failed'
                using
                    detail = 'Invalid Request Payload',
                    hint = _create_form_question_result.validation_failure_message;
        end if;

        _create_form_question_settings_result := forms.create_form_question_settings(
            jsonb_build_object(
                'form_question_id', (_create_form_question_result.created_form_question).form_question_id,
                'is_required', false
            )
        );

        if _create_form_question_settings_result.validation_failure_message is not null then
            raise exception 'Form Template Question Settings Creation Failed'
                using
                    detail = 'Invalid Request Payload',
                    hint = _create_form_question_settings_result.validation_failure_message;
        end if;

        _create_form_question_options_result := forms.create_form_question_options(
            (_create_form_question_result.created_form_question).form_question_id,
            jsonb_build_array(
                jsonb_build_object(
                    'option_text', 'Option 1',
                    'option_position', 1
                ),
                jsonb_build_object(
                    'option_text', 'Option 2',
                    'option_position', 2
                )
            )
        );

        if _create_form_question_options_result.validation_failure_message is not null then
            raise exception 'Form Template Question Options Creation Failed'
                using
                    detail = 'Invalid Request Payload',
                    hint = _create_form_question_options_result.validation_failure_message;
        end if;

        _create_form_question_default_option_result := forms.create_form_question_default_option(
            (_create_form_question_result.created_form_question).form_question_id,
            (_create_form_question_options_result.created_form_question_options[1]).form_question_option_id
        );
    end if;

    return jsonb_build_object(
        'form_question_sets', to_jsonb(forms.form_section_question_sets(form_section_id)),
        'form_questions', to_jsonb(forms.form_section_questions(form_section_id))
    );
end;
$$;

grant execute on function api.create_form_template_question_set(bigint, forms.form_question_set_type, int, bigint, bigint) to authenticated;

create type forms.form_question_option_mapping as (
    source_form_question_option_id bigint,
    new_form_question_option_id bigint
);

create or replace function forms.duplicate_form_question_option(_form_question_option forms.form_question_option, _new_form_question_id bigint) returns bigint
    language plpgsql
    security definer
as
$$
declare
    _new_form_question_option_id bigint;
begin
    insert into forms.form_question_option (form_question_id, option_text, option_position)
    values (_new_form_question_id, _form_question_option.option_text, _form_question_option.option_position)
    returning form_question_option_id into _new_form_question_option_id;

    return _new_form_question_option_id;
end;
$$;

create or replace function forms.duplicate_form_question_setting(_form_question_settings forms.form_question_settings, _new_form_question_id bigint) returns void
    language plpgsql
    security definer
as
$$
begin
    insert into forms.form_question_settings (form_question_id, helper_text, is_required, placeholder_text, minimum_length, maximum_length, minimum_date, maximum_date, display_type)
    values (_new_form_question_id, _form_question_settings.helper_text, _form_question_settings.is_required, _form_question_settings.placeholder_text, _form_question_settings.minimum_length, _form_question_settings.maximum_length, _form_question_settings.minimum_date, _form_question_settings.maximum_date, _form_question_settings.display_type);
end;
$$;

create or replace function forms.duplicate_form_question(
    _form_question forms.form_question,
    _new_form_question_set_id bigint
) returns forms.form_question_option_mapping[]
    language plpgsql
    security definer
as
$$
declare
    _new_form_question_id bigint;
    _form_question_option forms.form_question_option;
    _form_question_settings forms.form_question_settings := forms.form_question_settings(_form_question.form_question_id);
    _form_question_option_mapping forms.form_question_option_mapping[];
    _new_option_id bigint;
begin
    insert into forms.form_question (form_question_set_id, form_question_prompt, form_question_type, form_question_position)
    values (_new_form_question_set_id, _form_question.form_question_prompt, _form_question.form_question_type, _form_question.form_question_position)
    returning form_question_id into _new_form_question_id;

    _form_question_option_mapping := array[]::forms.form_question_option_mapping[];
    for _form_question_option in select * from forms.form_question_options(_form_question.form_question_id)
    loop
        _new_option_id := forms.duplicate_form_question_option(_form_question_option, _new_form_question_id);
        _form_question_option_mapping := _form_question_option_mapping ||
            row(_form_question_option.form_question_option_id, _new_option_id)::forms.form_question_option_mapping;
    end loop;

    perform forms.duplicate_form_question_setting(_form_question_settings, _new_form_question_id);

    return _form_question_option_mapping;
end;
$$;

create or replace function forms.form_question_set_questions(_form_question_set_id bigint) returns forms.form_question[]
    language sql
    stable
as
$$
    select coalesce(array_agg(fq order by fq.form_question_position), array[]::forms.form_question[])
    from forms.form_question fq
    where fq.form_question_set_id = _form_question_set_id;
$$;

create or replace function forms.child_form_question_sets(_form_question_set_id bigint) returns forms.form_question_set[]
    language sql
    stable
as
$$
    select coalesce(array_agg(fqs order by fqs.form_question_set_position), array[]::forms.form_question_set[])
    from forms.form_question_set fqs
    where fqs.parent_form_question_set_id = _form_question_set_id;
$$;

create or replace function forms.form_section_root_question_sets(_form_section_id bigint) returns forms.form_question_set[]
    language sql
    stable
as
$$
    select coalesce(array_agg(fqs order by fqs.form_question_set_position), array[]::forms.form_question_set[])
    from forms.form_question_set fqs
    where fqs.form_section_id = _form_section_id
    and fqs.parent_form_question_set_id is null;
$$;

create or replace function forms.duplicate_form_question_set(
    _form_question_set forms.form_question_set,
    _new_form_section_id bigint,
    _new_parent_form_question_set_id bigint,
    _parent_option_mapping forms.form_question_option_mapping[] default null
) returns void
    language plpgsql
    security definer
as
$$
declare
    _new_form_question_set_id bigint;
    _form_question forms.form_question;
    _child_form_question_set forms.form_question_set;
    _form_question_option_mapping forms.form_question_option_mapping[];
    _new_depends_on_option_id bigint;
begin
    if _parent_option_mapping is not null and _form_question_set.depends_on_option_id is not null then
        select pom.new_form_question_option_id
        into _new_depends_on_option_id
        from unnest(_parent_option_mapping) pom
        where pom.source_form_question_option_id = _form_question_set.depends_on_option_id;
    end if;

    insert into forms.form_question_set (
        form_section_id,
        form_question_set_type,
        form_question_set_position,
        depends_on_option_id,
        parent_form_question_set_id
    )
    values (
        _new_form_section_id,
        _form_question_set.form_question_set_type,
        _form_question_set.form_question_set_position,
        _new_depends_on_option_id,
        _new_parent_form_question_set_id
    )
    returning form_question_set_id into _new_form_question_set_id;

    for _form_question in select * from forms.form_question_set_questions(_form_question_set.form_question_set_id)
    loop
        _form_question_option_mapping := forms.duplicate_form_question(_form_question, _new_form_question_set_id);
    end loop;

    for _child_form_question_set in select * from forms.child_form_question_sets(_form_question_set.form_question_set_id) loop
        perform forms.duplicate_form_question_set(
            _child_form_question_set,
            _new_form_section_id,
            _new_form_question_set_id,
            _form_question_option_mapping
        );
    end loop;
end;
$$;

create or replace function api.repeat_application_form_question_set(form_question_set_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _form_question_set forms.form_question_set;
    _new_form_question_set_position int;
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

    return jsonb_build_object(
        'form_question_sets', to_jsonb(forms.form_section_question_sets(_form_question_set.form_section_id)),
        'form_questions', forms.form_section_questions(_form_question_set.form_section_id, true)
    );
end;
$$;

grant execute on function api.repeat_application_form_question_set(bigint) to authenticated;

create or replace function forms.duplicate_form_section(_form_section forms.form_section, _new_form_category_id bigint) returns void
    language plpgsql
    security definer
as
$$
declare
    _new_form_section_id bigint;
    _form_question_set forms.form_question_set;
begin
    -- Create a new form section and all the question sets inside the existing section using
    insert into forms.form_section (form_category_id, section_name, section_position)
    values (_new_form_category_id, _form_section.section_name, _form_section.section_position)
    returning form_section_id into _new_form_section_id;

    -- duplicate_form_question_set
    for _form_question_set in select * from forms.form_section_root_question_sets(_form_section.form_section_id) loop
        perform forms.duplicate_form_question_set(_form_question_set, _new_form_section_id, null);
    end loop;
end;
$$;

create or replace function forms.form_category_sections(_form_category_id bigint) returns forms.form_section[]
    language sql
    stable
as
$$
    select coalesce(array_agg(fs order by fs.section_position), array[]::forms.form_section[])
    from forms.form_section fs
    where fs.form_category_id = _form_category_id;
$$;

create or replace function forms.duplicate_form_category(_form_category forms.form_category, _new_form_id bigint) returns void
    language plpgsql
    security definer
as
$$
declare
    _new_form_category_id bigint;
    _form_section forms.form_section;
begin
    -- Create a new form category
    insert into forms.form_category (form_id, category_name, category_position)
    values (_new_form_id, _form_category.category_name, _form_category.category_position)
    returning form_category_id into _new_form_category_id;

    -- Create new sections for all the existing category's sections
    for _form_section in select * from forms.form_category_sections(_form_category.form_category_id) loop
        perform forms.duplicate_form_section(_form_section, _new_form_category_id);
    end loop;
end;
$$;

create or replace function forms.form_categories(_form_id bigint) returns forms.form_category[]
    language sql
    stable
as
$$
    select coalesce(array_agg(fc order by fc.category_position), array[]::forms.form_category[])
    from forms.form_category fc
    where fc.form_id = _form_id;
$$;

create or replace function forms.duplicate_form(_form_id bigint, _created_by bigint) returns bigint
    language plpgsql
    security definer
as
$$
declare
    _new_form_id bigint;
    _form_category forms.form_category;
begin
    insert into forms.form (created_by)
    values (_created_by)
    returning form_id into _new_form_id;

    for _form_category in select * from forms.form_categories(_form_id) loop
        perform forms.duplicate_form_category(_form_category, _new_form_id);
    end loop;

    return _new_form_id;
end;
$$;

create table if not exists applications.application_form(
    application_form_id bigint default utils.generate_random_id() not null primary key,
    organization_id bigint not null references organizations.organization(organization_id) on delete cascade,
    application_id bigint not null references applications.application(application_id) on delete cascade,
    form_id bigint not null references forms.form(form_id) on delete cascade,
    created_by bigint references users.user(user_id) on delete set null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create or replace function applications.create_application_form(_organization_id bigint, _application_id bigint, _form_id bigint, _created_by bigint) returns bigint
    language plpgsql
    security definer
as
$$
declare
    _application_form_id bigint;
begin
    insert into applications.application_form (organization_id, application_id, form_id, created_by)
    values (_organization_id, _application_id, _form_id, _created_by)
    returning application_form_id into _application_form_id;

    return _application_form_id;
end;
$$;

create or replace function api.create_application_form(application_id bigint, form_template_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _existing_form_id bigint := forms.form_id_by_form_template_id(form_template_id);
    _new_form_id bigint;
    _application_form_id bigint;
    _create_application_update_result record;
begin
    if _current_user_role not in ('org_admin', 'org_owner') then
        raise exception 'Form Creation Failed'
            using
                detail = 'You are not authorized to create a form',
                hint = 'unauthorized';
    end if;

    if _existing_form_id is null then
        raise exception 'Form Creation Failed'
            using
                detail = 'The form template was not found',
                hint = 'form_template_not_found';
    end if;

    _new_form_id := forms.duplicate_form(
        _existing_form_id,
        auth.current_user_id()
    );

    _application_form_id := applications.create_application_form(
        auth.current_user_organization_id(),
        application_id,
        _new_form_id,
        auth.current_user_id()
    );

    _create_application_update_result := applications.create_application_update(
        application_id,
        'new_form_added',
        auth.current_user_id(),
        null,
        null
    );

    return jsonb_build_object(
        'application_form_id', _application_form_id
    );
end;
$$;

grant execute on function api.create_application_form(bigint, bigint) to authenticated;

create or replace function api.application_forms(application_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _application_forms jsonb;
begin
    if (_current_user_role = 'org_client' and applications.application_user_id(application_id) != auth.current_user_id())
    or _current_user_role not in ('org_admin', 'org_owner', 'org_client') then
        raise exception 'Application Forms Retrieval Failed'
            using
                detail = 'You are not authorized to retrieve application forms',
                hint = 'unauthorized';
    end if;

    select jsonb_agg(
        to_jsonb(af) || jsonb_build_object(
            'form', to_jsonb(f)
        )
    )
    into _application_forms
    from applications.application_form af
    join forms.form f on f.form_id = af.form_id
    where af.application_id = $1
    and af.organization_id = auth.current_user_organization_id();

    return _application_forms;
end;
$$;

grant execute on function api.application_forms(bigint) to authenticated;

create or replace function applications.application_form_owner_id(_application_form_id bigint) returns bigint
    language sql
    stable
as
$$
    select
        a.user_id
    from applications.application a
    join applications.application_form af
    using (application_id)
    where af.application_form_id = _application_form_id;
$$;

create or replace function api.application_form_categories_and_sections(application_form_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _application_form applications.application_form;
    _form forms.form;
    _application_form_categories jsonb;
    _application_form_sections jsonb;
begin
    if (_current_user_role = 'org_client' and applications.application_form_owner_id(application_form_id) != auth.current_user_id())
    or _current_user_role not in ('org_admin', 'org_owner', 'org_client') then
        raise exception 'Application Forms Retrieval Failed'
            using
                detail = 'You are not authorized to retrieve application forms',
                hint = 'unauthorized';
    end if;

    select *
    into _application_form
    from applications.application_form af
    where af.application_form_id = $1
    and organization_id = auth.current_user_organization_id();

    select *
    into _form
    from forms.form
    where form_id = _application_form.form_id;

    -- Select form categories with completion_rate
    select jsonb_agg(
        to_jsonb(fc) || jsonb_build_object('completion_rate', 0)
        order by fc.category_position
    )
    into _application_form_categories
    from forms.form_category fc
    where fc.form_id = _application_form.form_id;

    -- Select form sections with completion_rate
    select jsonb_agg(
        to_jsonb(fs) || jsonb_build_object('completion_rate', 0)
        order by fs.section_position
    )
    into _application_form_sections
    from forms.form_section fs
    where fs.form_category_id = any(
        select form_category_id
        from forms.form_category
        where form_id = _application_form.form_id
    );

    return jsonb_build_object(
        'application_form', to_jsonb(_application_form) || jsonb_build_object(
            'form', to_jsonb(_form)
        ),
        'form_categories', coalesce(_application_form_categories, '[]'::jsonb),
        'form_sections', coalesce(_application_form_sections, '[]'::jsonb)
    );
end;
$$;

grant execute on function api.application_form_categories_and_sections(bigint) to authenticated;

create or replace function forms.form_section_application_form_id(form_section_id bigint) returns bigint
    language sql
    stable
as
$$
    select af.application_form_id
    from applications.application_form af
    join forms.form_category fc
    using (form_id)
    join forms.form_section fs
    using (form_category_id)
    where fs.form_section_id = $1;
$$;


create or replace function api.application_form_section_question_sets_and_questions(form_section_id bigint, include_answers boolean default false) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_user_role users.user_role := auth.current_user_role();
    _application_form_id bigint := forms.form_section_application_form_id(form_section_id);
begin
    if (_current_user_role = 'org_client' and applications.application_form_owner_id(_application_form_id) != auth.current_user_id())
    or _current_user_role not in ('org_admin', 'org_owner', 'org_client') then
        raise exception 'Form Template Section Question Sets And Questions Retrieval Failed'
            using
                detail = 'You are not authorized to retrieve the form template section question sets and questions',
                hint = 'unauthorized';
    end if;

    return jsonb_build_object(
        'form_question_sets', to_jsonb(forms.form_section_question_sets(form_section_id)),
        'form_questions', forms.form_section_questions(form_section_id, include_answers)
    );
end;
$$;

grant execute on function api.application_form_section_question_sets_and_questions(bigint, boolean) to authenticated;

create table if not exists forms.form_answer(
    form_answer_id bigint default utils.generate_random_id() not null primary key,
    form_question_id bigint not null unique references forms.form_question(form_question_id) on delete cascade,
    answer_text text,
    answer_date date,
    is_acceptable boolean default false not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists forms.form_answer_file(
    form_answer_id bigint not null references forms.form_answer(form_answer_id) on delete cascade,
    file_id bigint not null references files.file(file_id) on delete cascade,
    created_at timestamptz not null default now()
);

create table if not exists forms.form_answer_option(
    form_answer_id bigint not null references forms.form_answer(form_answer_id) on delete cascade,
    form_question_option_id bigint not null references forms.form_question_option(form_question_option_id) on delete cascade,
    created_at timestamptz not null default now()
);

create or replace function forms.form_question_answer(_form_question_id bigint) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _organization_config organizations.organization_config;
begin
    _organization_config := organizations.config_by_org_id(auth.current_user_organization_id());

    return (
        select to_jsonb(fa) || jsonb_build_object(
            'answer_options', coalesce((
                select jsonb_agg(to_jsonb(fao))
                from forms.form_answer_option fao
                where fao.form_answer_id = fa.form_answer_id
            ), '[]'::jsonb),
            'answer_files', coalesce((
                select jsonb_agg(to_jsonb(af) || jsonb_build_object(
                    'file', jsonb_build_object(
                        'file_id', f.file_id,
                        'name', f.name,
                        'mime_type', f.mime_type,
                        'size', f.size,
                        'url', aws.generate_s3_presigned_url(
                            _organization_config.s3_bucket,
                            f.object_key,
                            _organization_config.s3_region,
                            'GET',
                            3600
                        ),
                        'created_at', f.created_at,
                        'updated_at', f.updated_at
                    )
                ))
                from forms.form_answer_file af
                join files.file f using (file_id)
                where af.form_answer_id = fa.form_answer_id
            ), '[]'::jsonb)
        )
        from forms.form_answer fa
        where fa.form_question_id = _form_question_id
    );
end;
$$;

create or replace function forms.validate_create_form_answer_option_input(
    _form_answer_id bigint,
    _form_question_option_id bigint
) returns text
    language plpgsql
    security definer
as
$$
begin
    if _form_answer_id is null or _form_answer_id <= 0 then
        return 'missing_form_answer_id';
    end if;

    if _form_question_option_id is null or _form_question_option_id <= 0 then
        return 'missing_form_question_option_id';
    end if;

    if not exists (
        select 1
        from forms.form_answer fa
        where fa.form_answer_id = _form_answer_id
    ) then
        return 'form_answer_not_found';
    end if;

    if not exists (
        select 1
        from forms.form_question_option fqo
        join forms.form_answer fa
        using (form_question_id)
        where fqo.form_question_option_id = _form_question_option_id
    ) then
        return 'form_question_option_not_found';
    end if;

    return null;
end;
$$;

create or replace function forms.create_form_answer_option(
    _form_answer_id bigint,
    _form_question_option_id bigint,
    out validation_failure_message text,
    out created_form_answer_option forms.form_answer_option
) returns record
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := forms.validate_create_form_answer_option_input(_form_answer_id, _form_question_option_id);
    if validation_failure_message is not null then
        return;
    end if;

    insert into forms.form_answer_option (
        form_answer_id,
        form_question_option_id
    ) values (
        _form_answer_id,
        _form_question_option_id
    )
    returning * into created_form_answer_option;

    return;
end;
$$;

create or replace function forms.validate_create_form_answer_file_input(
    _form_answer_id bigint,
    _file_id bigint
) returns text
    language plpgsql
as
$$
begin
    if _form_answer_id is null or _form_answer_id <= 0 then
        return 'missing_form_answer_id';
    end if;

    if _file_id is null or _file_id <= 0 then
        return 'missing_file_id';
    end if;

    if not exists (
        select 1
        from forms.form_answer fa
        where fa.form_answer_id = _form_answer_id
    ) then
        return 'form_answer_not_found';
    end if;

    if not exists (
        select 1
        from files.file f
        where f.file_id = _file_id
        and f.organization_id = auth.current_user_organization_id()
    ) then
        return 'file_not_found';
    end if;

    return null;
end;
$$;

create or replace function forms.create_form_answer_file(
    _form_answer_id bigint,
    _file_id bigint,
    out validation_failure_message text,
    out created_form_answer_file forms.form_answer_file
) returns record
    language plpgsql
    security definer
as
$$
begin
    validation_failure_message := forms.validate_create_form_answer_file_input(_form_answer_id, _file_id);
    if validation_failure_message is not null then
        return;
    end if;

    insert into forms.form_answer_file (
        form_answer_id,
        file_id
    ) values (
        _form_answer_id,
        _file_id
    )
    returning * into created_form_answer_file;

    return;
end;
$$;

create or replace function forms.is_textarea_answer_acceptable(
    _form_question_id bigint,
    _answer_text text
) returns boolean
    language plpgsql
    security definer
as
$$
declare
    _form_question_settings forms.form_question_settings := forms.form_question_settings(_form_question_id);
    _text_length int := coalesce(length(_answer_text), 0);
begin
    if _form_question_settings.minimum_length is not null 
       and _text_length < _form_question_settings.minimum_length then
        return false;
    end if;

    if _form_question_settings.maximum_length is not null 
       and _text_length > _form_question_settings.maximum_length then
        return false;
    end if;

    return true;
end;
$$;

create or replace function forms.is_date_answer_acceptable(
    _form_question_id bigint,
    _answer_date date
) returns boolean
    language plpgsql
    security definer
as
$$
declare
    _form_question_settings forms.form_question_settings := forms.form_question_settings(_form_question_id);
begin
    if _form_question_settings.minimum_date is not null 
       and _answer_date < _form_question_settings.minimum_date then
        return false;
    end if;

    if _form_question_settings.maximum_date is not null 
       and _answer_date > _form_question_settings.maximum_date then
        return false;
    end if;

    return true;
end;
$$;

create or replace function forms.form_question_type(
    _form_question_id bigint
) returns text
    language sql
    stable
as
$$
    select fq.form_question_type
    from forms.form_question fq
    where fq.form_question_id = $1;
$$;

create or replace function forms.validate_upsert_form_answer_input(
    _form_question_id bigint
) returns text
    language plpgsql
    security definer
as
$$
begin
    if _form_question_id is null or _form_question_id = 0 then
        return 'form_question_id_required';
    end if;

    if not exists (
        select 1
        from forms.form_question fq
        where fq.form_question_id = _form_question_id
    ) then
        return 'form_question_not_found';
    end if;

    return null;
end;
$$;

create or replace function forms.upsert_form_answer(
    _form_question_id bigint,
    _answer_text text default null,
    _answer_date date default null,
    out upserted_form_answer forms.form_answer,
    out validation_failure_message text
) returns record
    language plpgsql
    security definer
as
$$
declare
    _is_acceptable boolean;
    _form_question_type text := forms.form_question_type(_form_question_id);
begin
    validation_failure_message := forms.validate_upsert_form_answer_input(_form_question_id);
    if validation_failure_message is not null then
        return;
    end if;

    case _form_question_type
        when 'textarea' then
            _is_acceptable := forms.is_textarea_answer_acceptable(_form_question_id, _answer_text);
        when 'date' then
            _is_acceptable := forms.is_date_answer_acceptable(_form_question_id, _answer_date);
        else
            _is_acceptable := true;
    end case;

    insert into forms.form_answer (
        form_question_id,
        answer_text,
        answer_date,
        is_acceptable
    ) values (
        _form_question_id, 
        _answer_text, 
        _answer_date,
        _is_acceptable
    )
    on conflict (form_question_id) do update 
    set 
        answer_text = excluded.answer_text,
        answer_date = excluded.answer_date,
        is_acceptable = excluded.is_acceptable,
        updated_at = now()
    returning * into upserted_form_answer;
end;
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

    return jsonb_build_object(
        'form_answer', _updated_form_answer
    );
end;
$$;

grant execute on function api.upsert_form_answer(bigint, text, date, jsonb, jsonb) to authenticated;

create or replace function api.form_answer_file_upload_url(
    form_question_id bigint,
    file_name text,
    mime_type text
) returns jsonb
    language plpgsql
    security definer
as
$$
declare
    _current_org_id bigint := auth.current_user_organization_id();
    _current_user_role users.user_role := auth.current_user_role();
    _org_config organizations.organization_config;
    _object_key text;
begin
    if _current_user_role != 'org_client' then
        raise exception 'Form Answer File Upload URL Failed'
            using
                detail = 'You are not authorized to create a form answer file upload URL',
                hint = 'unauthorized';
    end if;

    _object_key := files.generate_object_key(
        _current_org_id,
        'form_answer_file',
        mime_type,
        file_name,
        form_question_id
    );

    _org_config := organizations.config_by_org_id(_current_org_id);

    return jsonb_build_object(
        'url', aws.generate_s3_presigned_url(
            _org_config.s3_bucket,
            _object_key,
            _org_config.s3_region,
            'PUT',
            3600
        ),
        'object_key', _object_key
    );
end;
$$;

grant execute on function api.form_answer_file_upload_url(bigint, text, text) to authenticated;

commit;
