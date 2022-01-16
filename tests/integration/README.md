Create `test-params.json`:

```json5
{
    "stack_name": "name your stack",
    "api_url": "get from stack output ApiUrl"
    // optional: "profile": "my-profile"
}
```

Commands:

```
pytest --stack-name $(jq -r .stack_name test-params.json) --api-url $(jq -r .api_url test-params.json)

# clear out DynamoDB table
python reset.py [--profile $(jq -r .profile test-params.json)] --stack-name $(jq -r .stack_name test-params.json)
```
