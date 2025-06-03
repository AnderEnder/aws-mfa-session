# aws-mfa-session
[![build status](https://github.com/AnderEnder/aws-mfa-session/workflows/Rust/badge.svg)](https://github.com/AnderEnder/aws-mfa-session/actions/workflows/rust.yml?query=branch%3Amaster)
[![build status](https://github.com/AnderEnder/aws-mfa-session/workflows/Release/badge.svg)](https://github.com/AnderEnder/aws-mfa-session/actions/workflows/release.yml)
[![codecov](https://codecov.io/gh/AnderEnder/aws-mfa-session/branch/master/graph/badge.svg)](https://codecov.io/gh/AnderEnder/aws-mfa-session)
[![crates.io](https://img.shields.io/crates/v/aws-mfa-session.svg)](https://crates.io/crates/aws-mfa-session)

A command line utility to generate temporary AWS credentials using virtual MFA devices. Credentials can be exported to environment variables, used in a new shell session, or saved to AWS credentials file.

## Features
* Supports MFA authentication with virtual MFA devices (hardware MFA devices supported, but FIDO security keys are not supported)
* Select any profile from AWS credentials file
* Automatic MFA device detection from user profile
* Generate temporary credentials using AWS STS
* Multiple output options:
  * Export as environment variables
  * Launch new shell with credentials
  * Update/create profiles in AWS credentials file

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

Could be used to inject variables into the current shell:
```sh
eval $(aws-mfa-session -c 464899 -e)
```

Generate session credentials with default profile and MFA ARN:

```sh
aws-mfa-session --arn arn:aws:iam::012345678910:mfa/username --code 123456 -e
```

Generate session credentials with default profile and non-default region:

```sh
aws-mfa-session --region us-east-2 --code 123456 -e
```

Generate session credentials with default profile, and run a new shell with exported environment variables:

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
aws-mfa-session --credentials-file ~/.aws/credentials2 --profile dev --update-profile mfa-session --code 123456
```

Generate session credentials with custom duration (2 hours):

```sh
aws-mfa-session --code 123456 --duration 7200 -e
```

Generate session credentials with maximum duration (36 hours):

```sh
aws-mfa-session --code 123456 --duration 129600 -e
```

## Installation

### Pre-built Binaries

Download pre-built binaries from the [GitHub Releases](https://github.com/AnderEnder/aws-mfa-session/releases) page for:

* Windows
* Linux
* macOS

### Build from Source

Requirements: Rust and Cargo

```sh
# Install latest from crates.io
cargo install aws-mfa-session

# Install latest from git
cargo install --git https://github.com/AnderEnder/aws-mfa-session

# Build from local source
git clone https://github.com/AnderEnder/aws-mfa-session
cd aws-mfa-session
cargo build --release

# Install from local source
cargo install --path .
```

## Usage

```
Usage: aws-mfa-session [OPTIONS] --code <CODE>

Options:
  -p, --profile <PROFILE>
          AWS credential profile to use. AWS_PROFILE is used by default
  -f, --credentials-file <FILE>
          AWS credentials file location to use. AWS_SHARED_CREDENTIALS_FILE is used if not defined
  -r, --region <REGION>
          AWS region. AWS_REGION is used if not defined
  -c, --code <CODE>
          MFA code from MFA resource
  -a, --arn <ARN>
          MFA device ARN from user profile. It could be detected automatically
  -d, --duration <DURATION>
          Session duration in seconds (900-129600) [default: 3600]
  -s
          Run shell with AWS credentials as environment variables
  -e
          Print(export) AWS credentials as environment variables
  -u, --update-profile <SESSION_PROFILE>
          Update AWS credential profile with temporary session credentials
  -h, --help
          Print help
```
