AWS AND PYTHON JohnBrice Workshop

Tutorial to work with boto3

The script creates two s3 buckets by defined prefix name slavap13-jb-.
If a bucket name with a defined prefix already exists it uses this bucket.
This allows running script multiple times without creating duplicate resources

In order to delete all AWS resources run the script with a argument delete 
For example: python aws_boto3_jb_project_ex.py delete




