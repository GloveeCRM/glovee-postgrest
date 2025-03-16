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

    if not found then
        return json_build_object(
            'message', 'File not found'
        );
    end if;
    
    return json_build_object(
            'file_id', _file_details.file_id,
            'object_key', _file_details.object_key,
            'bucket', _file_details.bucket,
            'region', _file_details.region
   );
end;
$$;

grant execute on function services_api.file_details(bigint) to s3_presigner_service;

create or replace function services_api.file_upload_details(
    org_name text,
    file_name text,
    mime_type text,
    purpose text,
    parent_entity_id bigint default null
) returns jsonb
security definer
language plpgsql
as
$$
declare
    _target_org_id bigint := organizations.org_id_by_org_name(org_name);
    _org_config organizations.organization_config := organizations.config_by_org_id(_target_org_id);
    _object_key text;
begin
    if purpose not in (
        'profile_picture',
        'organization_logo',
        'form_answer_file',
        'application_file'
    ) then
        raise exception 'File Upload Details Failed'
            using
                detail = 'Invalid purpose',
                hint = 'invalid_purpose';
    end if;

    if _target_org_id is null then
        raise exception 'File Upload Details Failed'
            using
                detail = 'Organization not found',
                hint = 'organization_not_found';
    end if;

    _object_key := files.generate_object_key(
        _target_org_id,
        purpose,
        mime_type,
        file_name,
        parent_entity_id
    );

    return jsonb_build_object(
        'region', _org_config.s3_region,
        'bucket', _org_config.s3_bucket,
        'object_key', _object_key
    );
end;
$$;

grant execute on function services_api.file_upload_details(text, text, text, text, bigint) to s3_presigner_service;

commit;