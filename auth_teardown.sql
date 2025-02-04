begin;

drop function if exists api.set_new_password(text, uuid, text);
drop function if exists users.validate_update_user_password_input(bigint, bigint, text);
drop function if exists users.update_user_password(bigint, bigint, text);
drop function if exists auth.reset_password_token_by_token(uuid);
drop function if exists api.forgot_password(text, text);
drop function if exists auth.validate_create_password_reset_token_input(bigint);
drop function if exists auth.create_password_reset_token(bigint);
drop table if exists auth.password_reset_token;

commit;
