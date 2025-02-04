begin;

drop function if exists comms.send_email(text, text, text, text, bigint);

drop table if exists comms.email;

drop schema if exists comms cascade;

commit;