# Certificate signing example

This directory contains the files and automation required to reproduce the
following scenario:

> Company ACME Inc. has its own PKI that consists of a
> root CA and several intermediate CAs.
>
> One intermediate CA is allocated to generate certificates that end users
> must use to sign their container images using `cosign`.

## Prerequisites

The following binaries must be available on the system:

- `make`
- `cfssl` and `cfssljson`: both can be be downloaded from [here](https://github.com/cloudflare/cfssl/releases)
- `cosign`

## Creating all the certificates

> **Note:** this step is optional, the `sign` and `verify` make targets
> are going to handle all of that automatically. This section is just to
> explain what happens behind the scene.

First of all the root CA must be generated, this can be done via:

```console
make ca
```

The CA is created using the settings specified inside of the `ca.json` file.

The next step is the creation of an intermediate CA, this is the
CA that is going to be used to issue the user certificates:

```console
make intermediate-ca
```

The intermediate CA is created using the settings from the `intermediate-ca.json`
and the values under the `intermediate_ca` profile defined inside of the `cfssl.json`.

It's worth to point out that the CA issuing the end user certificates must have
some specific x509 attributes, otherwise `cosign` will not consider the CA valid.
The `intermediate_ca` profile defines **only** the required usage attributes.

Finally, we can create a certificate for a test user who has the following
mail address: `user1@kubewarden.io`.

The certificate can be created in this way:

```console
make user
```

Again, the settings used to create this certificate are stored inside of the
`user-1.json` file and inside of the `sigstore` profile defined inside of the
`cfssl.json` file.

## Signing a container image

First of all, ensure the container image/kwctl policy is already pushed into
a container registry.

Then issue the following command:

```console
IMAGE=<OCI URL> make sign
```

For example, assuming we want to sign the `registry-testing.svc.lan/kubewarden/pod-privileged:v0.1.9`
policy, this would be the command to execute:

```console
IMAGE=registry-testing.svc.lan/kubewarden/pod-privileged:v0.1.9 make sign
```

You can see the actual `cosign` commands being printed on the standard output.

### Rekor integration

It's possible to sign the container image using a certificate and send the proof of
signature into Rekor's transparency log.

This can be done using the following command:

```console
IMAGE=<OCI URL> make sign-rekor
```

## Verifying a container image

This is done using the following command:

```console
IMAGE=<OCI URL> make verify
```

For example, assuming we want to verify the `registry-testing.svc.lan/kubewarden/pod-privileged:v0.1.9`
policy, this would be the command to execute:

```console
IMAGE=registry-testing.svc.lan/kubewarden/pod-privileged:v0.1.9 make verify
```

You can see the actual `cosign` commands being printed on the standard output.

## Create user certificate using a local Certificate Transparency log

This is really complex and most users will never do that. However, this can be accomplished
by running a local instance of [sunlight](https://github.com/FiloSottile/sunlight) to create
a local Certificate Transparency log.

First of all, create the certificate used by sunlight:

```console
make sunlight
```

This certificate is going to be signed by the root CA.

Then create the bundle:

```console
make bundle
```

Create a directory where all the sunlight data is going to be stored:

```console
mkdir ~/sunlight-data
cp bundle.pem ~/sunlight-data/chain.pem
cp -v sunlight*.pem ~/sunlight-data
```

Create a configuration file for sunlight undeer `~/sunlight-data/sunlight.yaml`:

```yaml
listen: ":8080"

checkpoints: checkpoints.db

logs:
  - name: sunlight.127.0.0.1.sslip.io/2024h1
    shortname: bergamo2024h1
    # the day the sunlight process is started
    inception: 2024-06-26
    httpprefix: /2024h1
    roots: ./chain.pem
    key: ./key.pem
    cache: bergamo2024h1.db
    poolsize: 750
    # change these dates accordingly
    notafterstart: 2024-06-26T00:00:00Z
    notafterlimit: 2024-07-01T00:00:00Z
```

Finally, run sunlight:

```console
cd ~/sunlight-data
sqlite3 checkpoints.db "CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, body TEXT)"
sunlight -testcert
```

Ensure the root CA is trusted by the system, how to do that depends on the operating system.

Then create the user certificate:

```console
make user-ctl
```
