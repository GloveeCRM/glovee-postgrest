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
