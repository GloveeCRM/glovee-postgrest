-- Revoke grants individually with error handling
do $$
begin
    execute 'revoke select on api.organizations from anon';
exception when undefined_table or undefined_object then null;
end$$;

do $$
begin
    execute 'revoke execute on function api.register_client(text, text, text, text, text) from anon';
exception when undefined_function or undefined_object then null;
end$$;

do $$
begin
    execute 'revoke execute on function api.refresh_tokens(text) from anon';
exception when undefined_function or undefined_object then null;
end$$;

do $$
begin
    execute 'revoke execute on function api.login(text, text, text) from anon';
exception when undefined_function or undefined_object then null;
end$$;

begin;
-- Drop views
drop view if exists api.organizations;
drop view if exists api.clients;

-- Drop AWS function for presigned URLs
drop function if exists aws.generate_s3_presigned_url(text, text, text, text, int);

-- Drop file functions
drop function if exists files.get_file_extension_from_mimetype(text);
drop function if exists files.generate_object_key(bigint, text, text, text, bigint);

-- Drop API functionss
drop function if exists api.update_user(bigint, text, text, text, bigint);
drop function if exists api.update_user_status(bigint, users.user_status);
drop function if exists api.create_client(text, text, text, text);
drop function if exists api.register_client(text, text, text, text, text);
drop function if exists api.refresh_tokens(text);
drop function if exists api.login(text, text, text);

-- Drop user functions
drop function if exists users.update_user(bigint, text, text, text, bigint);
drop function if exists users.validate_update_user_input(bigint, text, text, text, bigint);
drop function if exists users.create_user_status(bigint, users.user_status);
drop function if exists users.validate_create_user_status_input(bigint, users.user_status);
drop function if exists users.create_user(text, text, text, text, text, users.user_role);
drop function if exists users.validate_create_user_input(text, text, text, text, text, users.user_role);
drop function if exists users.user_organization_id(bigint);

-- Drop auth functions
drop function if exists auth.generate_random_password();
drop function if exists auth.validate_current_user_org_access(text);
drop function if exists auth.refresh_tokens(text);
drop function if exists auth.validate_refresh_tokens_input(text);
drop function if exists auth.login(text, text, text);
drop function if exists auth.validate_login_input(text, text, text);
drop function if exists auth.current_user_id();
drop function if exists auth.current_user_role();
drop function if exists auth.current_user_organization_id();
drop function if exists auth.verify(text, text, text);
drop function if exists auth.try_cast_double(text);
drop function if exists auth.sign(jsonb, text, text);
drop function if exists auth.url_decode(text);
drop function if exists auth.algorithm_sign(text, text, text);
drop function if exists auth.url_encode(bytea);

-- Drop config functions
drop function if exists config.get(text);
drop function if exists config.item_from_app_settings(text);

-- Drop tables and constraints
alter table if exists organizations.organization drop constraint if exists logo_file_id_fk;
alter table if exists users.user drop constraint if exists profile_picture_file_id_fk;

drop table if exists config.config cascade;
drop table if exists files.file cascade;
drop table if exists organizations.organization_config cascade;
drop table if exists users.account_status cascade;
drop table if exists users.account_role cascade;
drop table if exists users.user cascade;
drop table if exists organizations.organization cascade;

-- Drop utility functions
drop function if exists utils.generate_random_id();

-- Drop domains
drop domain if exists users.user_role cascade;
drop domain if exists users.user_status cascade;

-- Drop extensions
drop extension if exists pgcrypto cascade;
drop extension if exists aws_lambda cascade;  -- if using aws_lambda extension

-- Drop schemas
drop schema if exists files cascade;
drop schema if exists utils cascade;
drop schema if exists auth cascade;
drop schema if exists organizations cascade;
drop schema if exists users cascade;
drop schema if exists config cascade;
drop schema if exists api cascade;
drop schema if exists aws cascade;

-- Drop roles
drop role if exists authenticated;
drop role if exists anon;
commit;
end;