# Database Setup and Migrations

This repository contains the database schema and migrations for the Glovee project. The database uses PostgreSQL.

## Prerequisites

- An instance of PostgreSQL server running
- A PostgreSQL superuser account
- A database named `gloveedb` already created
- A database user named `glovee` already created with permissions to create users

## Database Structure

The database initialization and migrations are organized as follows:

1. `init.sql` - **Run as superuser only**

   - Cleans up the database before running any migrations
   - Drops existing `anon` and `authenticated` roles
   - Cleans up the public schema with `glovee` as the owner
   - Revokes public privileges
   - Sets the search path to empty
   - Creates application roles (`anon` and `authenticated`)
   - Sets up migrations tracking system in `migrations` schema
   - Creates `utils` schema with helper functions
     - Includes `generate_random_id()` for unique ID generation

2. `migrations/` - **Run as glovee user**
   - Contains all database migrations in chronological order.

## Working with Migrations

### Creating a New Migration

1. Install the required dependencies:

   ```bash
   npm install
   ```

2. Generate a migration ID using the provided script:

   ```bash
   npm run migration:id your_migration_name
   ```

   The name must:

   - Start and end with a letter or number
   - Contain at least one lowercase letter
   - Only use lowercase letters, numbers, and underscores
     Example: `create_users_table`

3. Create a new SQL file in the `migrations/` directory using the generated ID:

   ```
   migrations/
   └── {generated_id}.sql
   ```

4. Write your migration SQL in the new file.

### Applying Migrations

1. Run the migration SQL using a db client or the `psql` command:

   ```bash
   psql -d gloveedb -U glovee -f migrations/{migration_file}.sql
   ```

2. Record the migration in the tracking table:
   ```sql
   execute migrations.create_migration(
       '{migration_id}',
       '{migration_content}'
   );
   ```
