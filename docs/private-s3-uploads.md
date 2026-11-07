# Private S3 uploads

All retained user uploads (verification photos and payment proofs) use the
backend's `PrivateFileStorageService`. The apps send files to the Z8 API; they
never receive AWS credentials or public S3 URLs. Cardholder photos submitted
from the admin form are staged in S3, sent to PhotonPay, then deleted from Z8
storage after the provider call completes.

## Bucket settings

- General purpose bucket in the account regional namespace.
- Keep Object Ownership at **Bucket owner enforced** (ACLs disabled).
- Keep all four **Block Public Access** settings enabled.
- Enable default **SSE-S3** encryption.
- Do not enable Object Lock. Keep versioning disabled until a lifecycle policy
  for noncurrent versions is in place.

## Backend configuration

Set these in `Backend_z8-card-flow/.env`:

```dotenv
PRIVATE_FILES_STORAGE=s3
AWS_REGION=eu-north-1
AWS_PROFILE=z8-uploads
S3_BUCKET=z8-uploads
PRIVATE_FILE_ENCRYPTION_KEY=<keep the existing value in .env>
PRIVATE_FILE_SIGNING_KEY=<keep the existing value in .env>
```

Keep the existing `PRIVATE_FILE_ENCRYPTION_KEY` and
`PRIVATE_FILE_SIGNING_KEY` stable. Uploaded file contents are encrypted by the
backend before they are written to S3; S3 also applies the bucket's default
encryption. Do not change or regenerate these keys after uploads exist.

`z8-uploads` is the bucket name currently configured in the local `.env`; use
the exact name shown in the S3 console if AWS changed it or you created a
different name. `eu-north-1` is Stockholm and must match the bucket's region.

The AWS SDK uses its standard credential chain. In production, attach a role to
the backend workload. For local development, use a dedicated IAM identity and
an AWS CLI profile; do not use root access keys or commit credentials.

On Windows, install AWS CLI v2, create the `z8-uploads` profile with
`aws configure --profile z8-uploads`, and enter the dedicated IAM access key
there. Keep its secret in the AWS credentials file, not in this repository or
chat. The `.env` profile name is not a credential.

Grant that role/profile only these object actions on
`arn:aws:s3:::YOUR_BUCKET_NAME/mp/private/*`:

- `s3:PutObject`
- `s3:GetObject`
- `s3:DeleteObject`

Policy example (replace the bucket placeholder):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::YOUR_BUCKET_NAME/mp/private/*"
    }
  ]
}
```

The backend does not need `s3:ListBucket` or public access. Replace the bucket
placeholder in the policy with the exact bucket name.

## Rollout note

Existing local files remain readable as a migration fallback. New uploads go to
S3 when `PRIVATE_FILES_STORAGE=s3`. Keep the old local storage volume until
existing local file references have been migrated or retired.
