# PostgREST + AWS Integration Notes

## Authentication Flow

- PostgREST uses JWT for stateless auth
- Key requirement: JWT must contain `role` claim
- Role claim used to check resource access permissions
- Basic setup: Add `authenticated` role first
- Can add specific roles in the `user` claim like `org_client`, `org_admin`
- Example JWT:

```json
{
  "exp": 1730618207,
  "iat": 1730614607,
  "role": "authenticated",
  "user": {
    "role": "org_admin",
    "email": "mahdi.mohaghegh2001@gmail.com",
    "status": "active",
    "user_id": 73060937185904,
    "organization_id": 12345678
  },
  "token_type": "access_token",
  "organization": {
    "org_name": "glovee",
    "organization_id": 12345678
  }
}
```

## Reference

[PostgREST Auth Docs](https://postgrest.org/en/v11/references/auth.html)

## Lambda Integration with Postgres

Initially, there was confusion leading to migration from DigitalOcean to AWS for PostgREST lambda integration. However, synchronous view calls proved problematic, and lambda cold start issues became apparent.

Current focus is on implementing asynchronous lambda calls and returning presigned URLs to clients. Considering moving presigned URL lambda calls to the frontend.

Implementation challenges included:

- Trust policy configuration
- IAM roles and permissions setup
- Custom policies management
- Multi-bucket and region object storage

### Pros of Postgres Lambda Integration

- Efficient for bulk operations
- Async processing capability
- More structured and manageable

### Cons of Postgres Lambda Integration

- Cold start latency issues
- Complex IAM/permission setup
- Trust policy configuration overhead
- AWS dependency

### Best Practices

- Use for batch operations
- Return data needed for frontend presigned URL calls
- Consider cold start impact for time-sensitive operations

## Postgres Lambda Call Behavior

### Default Behavior

- Postgres makes Lambda calls synchronously
- Each call blocks until response received
- 10,000 records result in 10,000 sequential calls

### Example Problem

```sql
-- This blocks sequentially
SELECT
  *,
  aws_lambda.invoke('get-presigned-url', json_build_object('key', object_key))
FROM large_table;
```

### Solutions

1. Batch Processing

```sql
-- Better: Process in chunks
SELECT array_agg(
  json_build_object('key', object_key)
)
FROM large_table
LIMIT 1000;
-- Send batch to Lambda
```

2. Async Processing Via Backend

- Move Lambda calls to application layer
- Use async/await patterns
- Return minimal data from Postgres

3. Consider pg_background

- For true async DB operations
- Adds complexity

### Trade-offs

- Sequential: Safe but slow
- Batching: Better performance, more complex
- Async Layer: Most flexible, requires architectural change

## What does postgrest do exactly? what happens before each query (on eacg request)

postgrest does this:
This is an example of what postgrest runs before each query, from a log dump:

```sql
2024-10-27 20:09:58.280 UTC [36] LOG:  execute 13: BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY
2024-10-27 20:09:58.281 UTC [36] LOG:  execute 14:

select
  set_config('search_path', $1, true),
  set_config('role', $2, true),
  set_config('request.jwt.claims', $3, true),
  set_config('request.method', $4, true),
  set_config('request.path', $5, true),
  set_config('request.headers', $6, true),
  set_config('request.cookies', $7, true)
2024-10-27 20:09:58.281 UTC [36] DETAIL:
  Parameters: $1 = '"api", "public"', $2 = 'web_anon', $3 = '{"role":"web_anon"}', $4 = 'GET', $5 = '/rpc/echo_postgrest_vars', $6 = '{"user-agent":"curl/8.10.1","host":"10.0.0.79:3000","accept":"*/*"}', $7 = '{}'

2024-10-27 20:09:58.283 UTC [36] LOG:  execute 15:

WITH pgrst_source AS (
  SELECT
    pgrst_call.pgrst_scalar
  FROM (
    SELECT $1 AS json_data
  ) pgrst_payload,
  LATERAL (
    SELECT "foo" FROM json_to_record(pgrst_payload.json_data) AS _("foo" text) LIMIT 1
  ) pgrst_body,
  LATERAL (
    SELECT "api"."echo_postgrest_vars"("foo" := pgrst_body."foo") pgrst_scalar
  ) pgrst_call
)
SELECT
  null::bigint AS total_result_set,
  1 AS page_total,
  coalesce(json_agg(_postgrest_t.pgrst_scalar)->0, 'null') AS body,
  nullif(current_setting('response.headers', true), '') AS response_headers,
  nullif(current_setting('response.status', true), '') AS response_status,
  '' AS response_inserted
FROM (
  SELECT "echo_postgrest_vars".* FROM "pgrst_source" AS "echo_postgrest_vars"
) _postgrest_t
2024-10-27 20:09:58.283 UTC [36] DETAIL:  Parameters: $1 = '{"foo":"bar"}'
2024-10-27 20:09:58.283 UTC [36] LOG:  execute 2: COMMIT
```

# Note for self: put the above into small understandable examples rather than copy pasting the dump.

## schema caching

One of the things that I missed as a first timer and kept shutting postgres down and turn on again was schema caching.

postgrest uses the postgres listen&notify pub/sub system to trigger reloading of the schema cache and the config
https://docs.postgrest.org/en/stable/references/listener.html#listener
(yes, that's right folks, postgresql has a built-in pub/sub system)

```sql
NOTIFY pgrst, 'reload schema'; -- reload schema cache
NOTIFY pgrst, 'reload config'; -- reload config
NOTIFY pgrst;                  -- reload both
```

What can happen in practice? When may I need to do this?

- when you change the schema, say if you add a function, and postgrest has not realised the function exists yet.

running the reload schema and config updates the api if it does not recognize the schema change so no need to shut postgrest doen when up.

references

- https://docs.postgrest.org/en/stable/references/schema_cache.html
- https://docs.postgrest.org/en/stable/references/configuration.html#config-reloading

### When would I need to shut down?

- When you update any of the parameters that can not be hot reloaded.
  see below for parameters:
- The list of parameters documents which cannot be hot-reloaded
  https://docs.postgrest.org/en/stable/references/configuration.html#config-full-list

## The basic idea: there are many disconnects in PostgREST tutorial, AI chatbot suggestoons and othet resources online.

- One of those disconnects I mentioned above. You can't figure out at first what is the connection between role that user has in JWT and the db role. why those role names? what checks thr privilages for that resource?

## Search and pagination

- Using views you can do search and pagination. However what was not so clear was how to get the total count of the search results. For that, you can easily just set the count parameter as exact in the header.
