# aws-mfa-session
[![build status](https://github.com/AnderEnder/aws-mfa-session/workflows/Rust/badge.svg)](https://github.com/AnderEnder/aws-mfa-session/actions)
[![codecov](https://codecov.io/gh/AnderEnder/aws-mfa-session/branch/master/graph/badge.svg)](https://codecov.io/gh/AnderEnder/aws-mfa-session)
[![crates.io](https://img.shields.io/crates/v/aws-mfa-session.svg)](https://crates.io/crates/aws-mfa-session)

A command line utility to generate temporary AWS credentials with virtual MFA device. Credentials could be exported into new shell or inserted into aws credentials file.

## Features
* support only virtual MFA devices (current limitation of API)
* select any profile from credential file
* detect MFA device from user profile
* generate temporary credentials (using sts)
* update profile in the credential file with generated credentials

## Release page distributions

Github Release page provides binaries for:

* Windows
* Linux
* macOS

## Examples

Generate session credentials with default profile, and print the credentials as exported environment variables

```sh
aws-mfa-session --code 123456 -e
```

Could be used to inject variables into the current shell
```sh
eval $(aws-mfa-session -c 464899 -e)
```

Generate session credentials with default profile and MFA arn:

```sh
aws-mfa-session --arn arn:aws:iam::012345678910:mfa/username --code 123456 -e
```

Generate session credentials with default profile and non-default region:

```sh
aws-mfa-session --region us-east2 --code 123456 -e
```

Generate session credentials with default profile, and run a new shell with new shell with exported environment variables

```sh
aws-mfa-session --code 123456 -s
```

Generate session credentials with default profile, and create or update a new profile:

```sh
aws-mfa-session --update-profile mfa-session --code 123456
```

Generate session credentials with defined profile, and create or update a new profile:

```sh
aws-mfa-session --profile dev --update-profile mfa-session --code 123456
```

Generate session credentials with defined profile and non-default credential file, and create or update a new profile:

```sh
aws-mfa-session --credentials-file .aws/credentials2 --profile dev --update-profile mfa-session --code 123456
```

## How to build and install

Requirements: rust and cargo

```sh
# Build
cargo build --release

# Install from local source
cargo install

# Install latest from git
cargo install --git https://github.com/AnderEnder/aws-mfa-session

# Install from crate package
cargo install aws-mfa-session
```