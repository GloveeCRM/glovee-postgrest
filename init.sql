/*
 * Database Initialization Script
 * Prerequisites:
 * - Must be executed by a superuser
 * - Database 'gloveedb' must exist
 * - Role 'glovee' must exist
 * 
 * This script:
 * 1. Removes existing roles and schemas
 * 2. Sets up basic security configuration
 * 3. Creates necessary roles and schemas
 * 4. Initializes migration tracking system
 */

begin;

-- Remove existing authentication roles for clean slate
drop role if exists anon;
drop role if exists authenticated;

-- Reset public schema to ensure clean initial state
-- Note: Requires superuser as 'glovee' is not the schema owner
drop schema if exists public cascade;

-- Initialize public schema with 'glovee' as owner
set role glovee;
create schema public;

-- Secure public schema by removing default privileges
-- This prevents unauthorized access to objects created in the future
revoke all on schema public from public;
revoke all on all functions in schema public from public;

-- Disable default public schema from search path
alter database gloveedb set search_path = '';

-- Create application-specific authentication roles
create role anon nologin noinherit;         -- Used for unauthenticated access
create role authenticated nologin noinherit; -- Used for authenticated users

-- Initialize migrations system
create schema migrations;

-- Track applied migrations with their content
create table migrations.migration (
    migration_id text not null primary key,
    content text not null,
    applied_at timestamp with time zone not null default now(),
    applied_by text not null default current_user
);

-- Helper function to record new migrations
create or replace function migrations.create_migration(
    _migration_id text,
    _content text
)
returns void 
language sql
as $$
    insert into migrations.migration (migration_id, content)
    values (_migration_id, _content);
$$ ;

-- Initialize utilities schema for helper functions
create schema utils;

-- ID generation function
-- Generates unique IDs based on timestamp and random number
-- Format: (epoch_timestamp % 1B * 100000) + random(0-99999)
-- Example: 73240262262612
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

commit;
