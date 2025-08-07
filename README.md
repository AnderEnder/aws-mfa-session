# aws-mfa-session
[![build status](https://github.com/AnderEnder/aws-mfa-session/workflows/Rust/badge.svg)](https://github.com/AnderEnder/aws-mfa-session/actions/workflows/rust.yml?query=branch%3Amaster)
[![build status](https://github.com/AnderEnder/aws-mfa-session/workflows/Release/badge.svg)](https://github.com/AnderEnder/aws-mfa-session/actions/workflows/release.yml)
[![codecov](https://codecov.io/gh/AnderEnder/aws-mfa-session/branch/master/graph/badge.svg)](https://codecov.io/gh/AnderEnder/aws-mfa-session)
[![crates.io](https://img.shields.io/crates/v/aws-mfa-session.svg)](https://crates.io/crates/aws-mfa-session)

A command line utility to generate temporary AWS credentials using virtual MFA devices. Credentials can be exported to environment variables, used in a new shell session, or saved to AWS credentials file.

## Features
* Supports MFA authentication with virtual MFA devices (hardware MFA devices supported, but FIDO security keys are not supported)
* **Interactive MFA code prompting** - if no code is provided, you'll be prompted to enter it
* Select any profile from AWS credentials file
* **Automatic MFA device selection** - reads `mfa_serial` from AWS profile configuration (~/.aws/config or ~/.aws/credentials), with fallback to automatic device detection
* Generate temporary credentials using AWS STS
* **Enhanced error reporting** with detailed error messages
* **Atomic credentials file updates** - prevents file corruption during concurrent access
* Multiple output options:
  * Export as environment variables
  * Launch new shell with credentials
  * Update/create profiles in AWS credentials file

## Release page distributions

GitHub Release page provides binaries for:

* Windows
* Linux
* macOS

## Configuration

### MFA Device Configuration

The tool can automatically select your MFA device by reading the `mfa_serial` setting from your AWS profile configuration. This eliminates the need to specify the `--arn` parameter each time.

#### Adding mfa_serial to ~/.aws/config (Recommended)

```ini
[profile dev]
region = us-west-2
mfa_serial = arn:aws:iam::123456789012:mfa/username

[profile prod]
region = eu-west-1
mfa_serial = arn:aws:iam::123456789012:mfa/prod-user
```

#### Adding mfa_serial to ~/.aws/credentials (Alternative)

```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
mfa_serial = arn:aws:iam::123456789012:mfa/username

[dev]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
mfa_serial = GAHT12345678
```

**Supported mfa_serial formats:**
- Virtual MFA devices: `arn:aws:iam::123456789012:mfa/username`
- Hardware MFA devices: `GAHT12345678` (serial number)

**Precedence:** Config file (~/.aws/config) takes precedence over credentials file (~/.aws/credentials).

## Examples

### Interactive MFA Code Entry

If you don't provide the `--code` argument, you'll be prompted to enter it interactively:

```sh
# Interactive mode - you'll be prompted for the MFA code
aws-mfa-session --export
Enter MFA code: 123456
```

### Automatic MFA Device Selection

When you have `mfa_serial` configured in your AWS profile, the tool automatically selects the MFA device:

```sh
# Uses mfa_serial from the default profile configuration
aws-mfa-session --code 123456 --export

# Uses mfa_serial from the dev profile configuration  
aws-mfa-session --profile dev --code 123456 --export
```

### Basic Usage

Generate session credentials with default profile, and print the credentials as exported environment variables:

```sh
aws-mfa-session --code 123456 --export
```

Could be used to inject variables into the current shell:
```sh
eval $(aws-mfa-session --code 464899 --export)
```

### Advanced Usage

Generate session credentials with default profile and MFA ARN:

```sh
aws-mfa-session --arn arn:aws:iam::012345678910:mfa/username --code 123456 --export
```

Generate session credentials with default profile and non-default region:

```sh
aws-mfa-session --region us-east-2 --code 123456 --export
```

Generate session credentials with default profile, and run a new shell with exported environment variables:

```sh
aws-mfa-session --code 123456 --shell
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
aws-mfa-session --code 123456 --duration 7200 --export
```

Generate session credentials with maximum duration (just under 36 hours):

```sh
aws-mfa-session --code 123456 --duration 129599 --export
```

### Shell-Specific Output Examples

The tool automatically detects your shell and formats output appropriately:

**Bash/Zsh/Sh output:**
```sh
export AWS_ACCESS_KEY_ID='AKIAIOSFODNN7EXAMPLE'
export AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
export AWS_SESSION_TOKEN='AQoEXAMPLE...'
export PS1='AWS:user@123456789012 \$ '
```

**Fish shell output:**
```fish
set -x AWS_ACCESS_KEY_ID "AKIAIOSFODNN7EXAMPLE"
set -x AWS_SECRET_ACCESS_KEY "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
set -x AWS_SESSION_TOKEN "AQoEXAMPLE..."
set -x PS1 "AWS:user@123456789012 \$ "
```

**CMD output:**
```cmd
set "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
set "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
set "AWS_SESSION_TOKEN=AQoEXAMPLE..."
set "PROMPT=AWS:user@123456789012 \$ "
```

**PowerShell output:**
```powershell
Set-Variable -Name "AWS_ACCESS_KEY_ID" -Value "AKIAIOSFODNN7EXAMPLE"
Set-Variable -Name "AWS_SECRET_ACCESS_KEY" -Value "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
Set-Variable -Name "AWS_SESSION_TOKEN" -Value "AQoEXAMPLE..."
function prompt { "AWS:user@123456789012 \$ " }
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
Usage: aws-mfa-session [OPTIONS]

Options:
  -p, --profile <PROFILE>
          AWS credential profile to use. AWS_PROFILE is used by default
  -f, --credentials-file <CREDENTIALS_FILE>
          AWS credentials file location to use. AWS_SHARED_CREDENTIALS_FILE is used if not defined
  -r, --region <REGION>
          AWS region. AWS_REGION is used if not defined
  -c, --code <CODE>
          MFA code from MFA resource
  -a, --arn <ARN>
          MFA device ARN from user profile. It could be detected automatically
  -d, --duration <DURATION>
          Session duration in seconds (900-129600) [default: 3600]
  -s, --shell
          Run shell with AWS credentials as environment variables
  -e, --export
          Print(export) AWS credentials as environment variables
  -u, --update-profile <SESSION_PROFILE>
          Update AWS credential profile with temporary session credentials
  -h, --help
          Print help
```

## Security Features

* **Input validation**: MFA codes must be exactly 6 digits
* **Duration validation**: Session duration is validated to be within AWS limits (15 minutes to 36 hours)
* **Atomic file operations**: Credentials file updates are atomic to prevent corruption
* **Permission preservation**: Original file permissions are maintained when updating credentials
* **Shell injection protection**: All shell output is properly escaped for security
* **Multi-shell support**: Supports Bash, Zsh, Fish, Sh, CMD, and PowerShell with proper prompt setting

## Shell Support

The application automatically detects your shell and formats output accordingly:

* **Unix/Linux shells**: Bash, Zsh, Sh, Fish
  - Sets `AWS_*` environment variables and `PS1` prompt
  - Proper quote escaping for special characters
* **Windows shells**: CMD, PowerShell
  - CMD: Uses `set` commands and `PROMPT` variable
  - PowerShell: Uses `Set-Variable` and custom `prompt` function
  - Case-insensitive shell detection

## Error Handling

The application provides detailed error messages with enhanced reporting using `miette`:

* **Input validation errors**: Invalid MFA codes, duration out of bounds
* **AWS service errors**: Authentication failures, missing MFA devices, STS token errors
* **File operation errors**: Permission issues, file corruption prevention
* **Network errors**: Connectivity issues, timeout handling
* **Interactive errors**: TTY detection for MFA code prompting

All errors include helpful context and suggestions for resolution.
