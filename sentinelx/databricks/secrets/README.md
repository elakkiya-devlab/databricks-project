# Secret Integration

`LiveCollector.databricks_secrets` lists scopes and keys only. Creation/rotation
history needs authoritative registry evidence. Approved renewal can put a new
bound OAuth client secret; inventory never calls get_secret.