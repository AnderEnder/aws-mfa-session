# aws-mfa-session
[![build status](https://github.com/AnderEnder/aws-mfa-session/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/AnderEnder/aws-mfa-session/actions/workflows/build.yml?query=branch%3Amaster)
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
* **Atomic credentials file updates** - the file is replaced via an atomic rename, preventing partial/torn writes
* **Comment-preserving edits** - only the session profile's keys change; comments, formatting and other settings stay as they were (see [`aws-shared-config`](https://github.com/AnderEnder/aws-shared-config))
* **Session reuse** - a session profile that is still valid is reused instead of asking for a new MFA code
* Multiple output options:
  * Export as environment variables for bash, zsh, sh, fish, cmd or PowerShell
  * Export as `credential_process` JSON
  * Launch new shell with credentials
  * Update/create profiles in AWS credentials file

## Release page distributions

GitHub Release page provides binaries for:

* Linux (x86_64 and ARM), in two flavors:
  * `aws-mfa-session-<arch>-linux.tar.gz`: a static musl binary that runs on any Linux, including Alpine and scratch containers
  * `aws-mfa-session-<arch>-linux-gnu.tar.gz`: a glibc binary for distributions with glibc 2.17 or newer (RHEL/CentOS 7, Ubuntu 14.04, Debian 8 and later)
* macOS (Apple Silicon and Intel)
* Windows (x86_64 and ARM)
* FreeBSD 14 or newer (x86_64)

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

**Section names** follow the AWS SDKs: profiles are `[profile name]` (or `[default]`) in `~/.aws/config` and `[name]` in `~/.aws/credentials`. Sections spelled otherwise are ignored, as the AWS SDKs ignore them.

## Examples

### Interactive MFA Code Entry

If you don't provide the `--code` argument, you'll be prompted to enter it interactively. The prompt appears only after your long-term credentials have been checked, so a misconfiguration is reported before you reach for your MFA device:

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
# bash, zsh, sh
eval "$(aws-mfa-session --code 464899 --export)"

# fish
aws-mfa-session --code 464899 --export | source

# PowerShell
aws-mfa-session --code 464899 --export --format powershell | Out-String | Invoke-Expression
```

The output format is detected from the `SHELL` environment variable. Use `--format` to choose it explicitly, for example on Windows, where `SHELL` is usually not set:

```sh
aws-mfa-session --code 123456 --export --format powershell
```

Print the credentials as JSON, in the format used by the AWS CLI's [`credential_process`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html):

```sh
aws-mfa-session --code 123456 --export --format json
```

```json
{
  "Version": 1,
  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "SessionToken": "AQoEXAMPLE...",
  "Expiration": "2026-10-18T15:04:05Z"
}
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

The profile records when the session expires (in an `expiration` key, which AWS tools ignore). While it has at least 15 minutes left, running the command again reuses it without asking for an MFA code — so it is safe to run at the start of every working session. Pass `--force` to request new credentials anyway, for example to switch the source `--profile` or get a longer `--duration`:

```sh
aws-mfa-session --update-profile mfa-session
Reusing profile 'mfa-session', valid until 2026-10-18T15:04:05Z (5h 12m left). Pass --force to renew it.

aws-mfa-session --update-profile mfa-session --force
```

A reused profile also feeds `--export` and `--shell`, so `aws-mfa-session -u mfa-session -e` prints the saved credentials while they are valid and only asks for a code once they are not.

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

### Using with AWS Assume Role

This tool works well with AWS assume role profiles. A common pattern is to use MFA-authenticated credentials as the source for assuming roles in other AWS accounts.

#### Basic Setup

1. **Base profile** (`~/.aws/credentials`) - contains your IAM user credentials:

```ini
[mycompany]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

2. **Profile configuration** (`~/.aws/config`) - defines MFA device and session profile:

```ini
[profile mycompany]
region = us-west-2
mfa_serial = arn:aws:iam::111111111111:mfa/username

[profile mycompany-session]
region = us-west-2
```

3. **Generate MFA session credentials**:

```sh
aws-mfa-session --profile mycompany --update-profile mycompany-session --code 123456
```

#### Assume Role Profiles

Now you can create assume role profiles that use the MFA-authenticated session as their source:

```ini
[profile dev-account]
region = us-west-2
output = json
source_profile = mycompany-session
role_arn = arn:aws:iam::222222222222:role/AdminRole

[profile prod-account]
region = us-west-2
output = json
source_profile = mycompany-session
role_arn = arn:aws:iam::333333333333:role/AdminRole
```

Use the profiles:

```sh
# After running aws-mfa-session to populate mycompany-session
aws s3 ls --profile dev-account
aws ec2 describe-instances --profile prod-account
```

#### Readonly Assume Role Profiles

AWS CLI supports session policies that restrict permissions when assuming a role. This is useful for creating "readonly" variants of your profiles that limit what actions can be performed, even if the underlying role has broader permissions.

Use `role_session_policy_arns` to attach AWS managed policies:

```ini
[profile dev-account-readonly]
region = us-west-2
output = json
source_profile = mycompany-session
role_arn = arn:aws:iam::222222222222:role/AdminRole
role_session_policy_arns = arn:aws:iam::aws:policy/ReadOnlyAccess

[profile prod-account-readonly]
region = us-west-2
output = json
source_profile = mycompany-session
role_arn = arn:aws:iam::333333333333:role/AdminRole
role_session_policy_arns = arn:aws:iam::aws:policy/ReadOnlyAccess
```

The session policy acts as an **intersection** with the role's permissions - you can only restrict permissions, not expand them beyond what the role allows.

**Other useful AWS managed policies for session restrictions:**

| Policy ARN | Description |
|------------|-------------|
| `arn:aws:iam::aws:policy/ReadOnlyAccess` | Read-only access to all AWS services |
| `arn:aws:iam::aws:policy/SecurityAudit` | Security audit access |
| `arn:aws:iam::aws:policy/ViewOnlyAccess` | View-only access (more restrictive than ReadOnly) |
| `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess` | Job function view-only access |

#### Custom Inline Session Policies

For more granular control, use `role_session_policy` with an inline JSON policy:

```ini
[profile dev-account-s3-readonly]
region = us-west-2
source_profile = mycompany-session
role_arn = arn:aws:iam::222222222222:role/AdminRole
role_session_policy = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":"*"}]}
```

**Note:** `role_session_policy_arns` requires AWS CLI v2.15.0 or later.

### Shell-Specific Output Examples

The tool detects your shell from `SHELL` (or uses `--format`) and formats output appropriately. `AWS_CREDENTIAL_EXPIRATION` is read by some AWS SDKs and prompt themes:

**Bash/Sh output** (zsh uses `%#` in the prompt instead of `\$`):
```sh
export AWS_ACCESS_KEY_ID='ASIAIOSFODNN7EXAMPLE'
export AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
export AWS_SESSION_TOKEN='AQoEXAMPLE...'
export AWS_CREDENTIAL_EXPIRATION='2026-10-18T15:04:05Z'
export PS1='AWS:user@123456789012 \$ '
```

**Fish shell output:**
```fish
set -gx AWS_ACCESS_KEY_ID 'ASIAIOSFODNN7EXAMPLE'
set -gx AWS_SECRET_ACCESS_KEY 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
set -gx AWS_SESSION_TOKEN 'AQoEXAMPLE...'
set -gx AWS_CREDENTIAL_EXPIRATION '2026-10-18T15:04:05Z'
function fish_prompt; echo -n 'AWS:user@123456789012> '; end
```

**CMD output:**
```cmd
set "AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE"
set "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
set "AWS_SESSION_TOKEN=AQoEXAMPLE..."
set "AWS_CREDENTIAL_EXPIRATION=2026-10-18T15:04:05Z"
set "PROMPT=AWS:user@123456789012$G "
```

**PowerShell output:**
```powershell
$env:AWS_ACCESS_KEY_ID = 'ASIAIOSFODNN7EXAMPLE'
$env:AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
$env:AWS_SESSION_TOKEN = 'AQoEXAMPLE...'
$env:AWS_CREDENTIAL_EXPIRATION = '2026-10-18T15:04:05Z'
function global:prompt { 'AWS:user@123456789012> ' }
```

## Installation

### Pre-built Binaries

Download pre-built binaries from the [GitHub Releases](https://github.com/AnderEnder/aws-mfa-session/releases) page for:

* Linux (x86_64 and ARM), in two flavors:
  * `aws-mfa-session-<arch>-linux.tar.gz`: a static musl binary that runs on any Linux, including Alpine and scratch containers
  * `aws-mfa-session-<arch>-linux-gnu.tar.gz`: a glibc binary for distributions with glibc 2.17 or newer (RHEL/CentOS 7, Ubuntu 14.04, Debian 8 and later)
* macOS (Apple Silicon and Intel)
* Windows (x86_64 and ARM)
* FreeBSD 14 or newer (x86_64)

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

### Cross-compiling

The release workflow builds the Linux and FreeBSD binaries on a single Linux runner with [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild), which needs [zig](https://ziglang.org/):

```sh
# Static musl binary
cargo zigbuild --release --target x86_64-unknown-linux-musl

# glibc binary that runs on glibc 2.17 or newer
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.17

# FreeBSD 14 or newer
cargo zigbuild --release --target x86_64-unknown-freebsd
```

Both macOS binaries are built on Apple Silicon; Xcode's toolchain targets Intel Macs directly:

```sh
rustup target add x86_64-apple-darwin
cargo build --release --target x86_64-apple-darwin
```

## Usage

```
Usage: aws-mfa-session [OPTIONS] <--shell|--export|--update-profile <SESSION_PROFILE>>

Options:
  -p, --profile <PROFILE>
          AWS credential profile to use. AWS_PROFILE is used by default
  -f, --credentials-file <CREDENTIALS_FILE>
          AWS credentials file location to use. AWS_SHARED_CREDENTIALS_FILE is used if not defined
  -r, --region <REGION>
          AWS region. AWS_REGION is used if not defined
  -c, --code <CODE>
          MFA code from MFA resource. Prompted for when not provided
  -a, --arn <ARN>
          MFA device ARN. If not provided, will try to read mfa_serial from AWS profile configuration, then fall back to automatic detection
  -d, --duration <DURATION>
          Session duration in seconds (900-129600) [default: 3600]
  -s, --shell
          Run shell with AWS credentials as environment variables
  -e, --export
          Print(export) AWS credentials as environment variables
      --format <FORMAT>
          Output format for --export. Detected from SHELL if not defined [possible values: bash, zsh, sh, fish, cmd, powershell, json]
  -u, --update-profile <SESSION_PROFILE>
          Update AWS credential profile with temporary session credentials. A profile that is still valid is reused
      --force
          Request new credentials even if the --update-profile profile is still valid
  -h, --help
          Print help
  -V, --version
          Print version
```

## Security Features

* **Input validation**: MFA codes must be exactly 6 digits
* **Duration validation**: Session duration is validated to be within AWS limits (15 minutes to 36 hours)
* **Atomic file operations**: Credentials file updates use an atomic rename to prevent partial/torn writes
* **Restrictive permissions**: On Unix, the credentials file is written with `0600` permissions (owner read/write only)
* **Shell injection protection**: All shell output is properly escaped for security
* **Multi-shell support**: Supports Bash, Zsh, Fish, Sh, CMD, and PowerShell with proper prompt setting

## Shell Support

The application automatically detects your shell and formats output accordingly:

* **Unix/Linux shells**: Bash, Zsh, Sh, Fish
  - Bash/Zsh/Sh: sets `AWS_*` environment variables and the `PS1` prompt
  - Fish: sets global exported variables and a `fish_prompt` function
  - Values are single-quoted using each shell's own escaping rules
* **Windows shells**: CMD, PowerShell
  - CMD: Uses `set` commands and `PROMPT` variable
  - PowerShell: Sets `$env:` environment variables (visible to the AWS CLI and other child processes) and a `prompt` function
* Detection uses the file name of `SHELL`, case-insensitively; override it with `--format`

## Error Handling

The application provides detailed error messages with enhanced reporting using `miette`:

* **Input validation errors**: Invalid MFA codes, duration out of bounds
* **AWS service errors**: Authentication failures, missing MFA devices, STS token errors
* **File operation errors**: Permission issues, file corruption prevention
* **Network errors**: Connectivity issues, timeout handling
* **Interactive errors**: TTY detection for MFA code prompting; an invalid code is asked for again

Errors name the AWS operation that failed and, where it helps, suggest a fix. For more detail when reporting a problem, set `RUST_LOG`, for example `RUST_LOG=aws_mfa_session=debug`; diagnostics are written to stderr, so they never mix with exported credentials.
