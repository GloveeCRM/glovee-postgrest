-- This query is used to clean up the database before running the migrations
-- It should be run by the superuser
-- A database named `gloveedb` should already exist
-- The role `glovee` should already exist

begin;

-- Drop roles `anon` and `authenticated`
drop role if exists anon;
drop role if exists authenticated;

-- Clean up public
-- Can only be dropped by the superuser since glovee is not the owner of the schema
drop schema if exists public cascade;

-- This sets the owner of the public schema to the role `glovee`
set role glovee;
create schema public;

-- Revoke all privileges from public
revoke all on schema public from public;
revoke all on all functions in schema public from public;

-- Set search path to none
alter database gloveedb set search_path = '';

commit;
