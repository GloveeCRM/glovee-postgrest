begin;

create schema organizations;

create table organizations.organization (
    organization_id bigint default utils.generate_random_id() not null primary key,
    name text,
    org_name text not null unique,
    logo_file_id bigint,
    created_at timestamp with time zone default now(),
    updated_at timestamp with time zone default now()
);

create table organizations.organization_config (
    organization_id bigint references organizations.organization(organization_id) on delete cascade,
    s3_bucket text not null,
    s3_region text not null,
    created_at timestamp with time zone default now(),
    updated_at timestamp with time zone default now(),
    constraint unique_org_config unique (organization_id)
);

create or replace function organizations.org_id_by_org_name(
    _org_name text
) returns bigint
security definer
language sql
as
$$
    select organization_id 
    from organizations.organization 
    where org_name = _org_name;
$$;

create or replace function organizations.org_config_by_org_id(
    _organization_id bigint
) returns organizations.organization_config
security definer
language plpgsql
as
$$
declare
    _config organizations.organization_config;
begin
    select * 
    into _config 
    from organizations.organization_config 
    where organization_id = _organization_id;
    return _config;
end;
$$;

commit;