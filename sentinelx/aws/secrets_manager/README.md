# AWS Secrets Manager

`LiveCollector.aws_secrets` uses boto3 pagination and DescribeSecret only.
The restricted renewal executor uses GetSecretValue only to load rollback material
into memory, puts AWSPENDING, then promotes AWSCURRENT after OAuth validation.