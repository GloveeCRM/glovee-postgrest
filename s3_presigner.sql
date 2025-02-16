begin;

create role s3_presigner_service nologin;

create schema services_api;

grant usage on schema services_api to s3_presigner_service;

create table auth.service_api_key (
    api_key text not null primary key,
    service_name text not null,
    created_at timestamp with time zone default now(),
    updated_at timestamp with time zone default now()
);

create or replace function auth.generate_service_api_key(
    _service_name text
) returns text
language plpgsql
security definer
as
$$
declare
    _api_key text;
    _api_key_claims jsonb;
    _api_key_secret text := config.item_from_app_settings('jwt_access_secret');
begin
    _api_key_claims := jsonb_build_object(
        'iat', extract(epoch from now())::int,
        'exp', extract(epoch from now() + interval '1 year')::int,
        'sub', _service_name,
        'role', 's3_presigner_service'
    );

    _api_key := auth.sign(_api_key_claims, _api_key_secret);
    return _api_key;
end;
$$;

create or replace function auth.create_service_api_key(
    _service_name text
) returns text
language plpgsql
as
$$
declare
    _api_key text := auth.generate_service_api_key(_service_name);
begin
    insert into auth.service_api_key (api_key, service_name)
    values (_api_key, _service_name);

    return _api_key;
end;
$$;

create or replace function services_api.file_details(
    file_id bigint
) returns jsonb
security definer
language plpgsql
as
$$
declare
    _file_details files.file;
begin
    select *
    into _file_details
    from files.file f
    where f.file_id = $1;

    return to_jsonb(_file_details);
end;
$$;

grant execute on function services_api.file_details(bigint) to s3_presigner_service;

commit;