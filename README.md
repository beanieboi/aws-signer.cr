# AWS Signer

This library signs your HTTP requests using AWS v4

## Installation


Add this to your application's `shard.yml`:

```yaml
dependencies:
  aws_signer:
    github: beanieboi/aws-signer.cr
```


## Usage


```crystal
require "aws_signer"

AwsSigner.configure do |config|
  config.access_key = "AKIDEXAMPLE"
  config.secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
  config.region = "us-east-1"
end

signed = AwsSigner.sign("GET", uri, headers, body)
signed["Authorization"]

```

## Contributing

see [CONTRIBUTING.md][contributing]

[contributing]: https://github.com/beanieboi/aws-signer.cr/blob/master/CONTRIBUTING.md

## Contributors

- [[beanieboi]](https://github.com/[beanieboi]) beanieboi - creator, maintainer
