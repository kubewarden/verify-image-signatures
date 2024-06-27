#!/usr/bin/env bats

@test "Accept a valid signature" {
  run kwctl run  --request-path test_data/pod_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature" {
  run kwctl run  --request-path test_data/pod_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*"message":"Pod invalid-pod-name is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Mutate Pod definition" {
  # Need to run the command inside of `bash -c` because of a bats
  # limitation: https://bats-core.readthedocs.io/en/stable/gotchas.html?highlight=pipe#my-piped-command-does-not-work-under-run
  run bash -c 'kwctl run \
    --request-path test_data/pod_creation_signed.json \
    --settings-path test_data/settings-mutation-enabled.yaml \
    annotated-policy.wasm 2>/dev/null | jq -er ".patch | @base64d"'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*ghcr.io/kubewarden/test-verify-image-signatures:signed@sha256:1d9d3da4c60d27b77bb96bba738319c1c4424853fdd10f65982f9f2ca2422a72.*') -ne 0 ]
}

@test "Do not mutate Pod definition" {
  # Need to run the command inside of `bash -c` because of a bats
  # limitation: https://bats-core.readthedocs.io/en/stable/gotchas.html?highlight=pipe#my-piped-command-does-not-work-under-run
  run bash -c 'kwctl run \
    --request-path test_data/pod_creation_signed.json \
    --settings-path test_data/settings-mutation-disabled.yaml \
    annotated-policy.wasm 2>/dev/null | jq -er ".patch"'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 1 ]
  [ $(expr "$output" : 'null') -ne 0 ]
}

@test "Accept a valid signature in a Deployment" {
  run kwctl run  --request-path test_data/deployment_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature in a Deployment" {
  run kwctl run  --request-path test_data/deployment_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Accept a valid signature in a StatefulSet" {
  run kwctl run  --request-path test_data/statefulset_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature in a StatefulSet" {
  run kwctl run  --request-path test_data/statefulset_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Accept a valid signature in a ReplicaSet" {
  run kwctl run  --request-path test_data/replicaset_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature in a ReplicaSet" {
  run kwctl run  --request-path test_data/replicaset_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Accept a valid signature in a ReplicationController" {
  run kwctl run  --request-path test_data/replicationcontroller_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature in a ReplicationController" {
  run kwctl run  --request-path test_data/replicationcontroller_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Accept a valid signature in a Job" {
  run kwctl run  --request-path test_data/job_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature in a Job" {
  run kwctl run  --request-path test_data/job_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Accept a valid signature in a CronJob" {
  run kwctl run  --request-path test_data/cronjob_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature in a CronJob" {
  run kwctl run  --request-path test_data/cronjob_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Certificate verification with Rekor enabled" {
  # This is a test that verifies an image that was signed with the
  # key associated with a certificate. The signature was then registered
  # inside of Rekor's transparency log.
  #
  # Need to run the command inside of `bash -c` because of a bats
  # limitation: https://bats-core.readthedocs.io/en/stable/gotchas.html?highlight=pipe#my-piped-command-does-not-work-under-run

  run bash -c 'kwctl run \
    --request-path test_data/pod_creation_signed_with_certificate.json \
    --settings-path test_data/settings-pod_signed_with_cert_and_rekor.yaml \
    annotated-policy.wasm | jq -r ".patch | @base64d"'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*ghcr.io/kubewarden/tests/pod-privileged:v0.2.1@sha256:db48aecd83c2826eba154a84c4fbabe0977f96b3360b4c6098578eae5c2d2882.*') -ne 0 ]
}

@test "Certificate verification with a wrong certificate chain" {
  run kwctl run \
    --request-path test_data/pod_creation_signed_with_certificate.json \
    --settings-path test_data/settings-cert-verification-wrong-cert-chain.yaml \
    annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 1 ]
  [ $(expr "$output" : '.*Provided settings are not valid.*') -ne 0 ]
  [ $(expr "$output" : '.*Certificate not trusted: Certificate is not trusted by the provided cert chain.*') -ne 0 ]
}

@test "Keyless verification" {
  # Need to run the command inside of `bash -c` because of a bats
  # limitation: https://bats-core.readthedocs.io/en/stable/gotchas.html?highlight=pipe#my-piped-command-does-not-work-under-run

  run bash -c 'kwctl run \
    --request-path test_data/pod_creation_signed_with_keyless_mode.json \
    --settings-path test_data/settings-keyless-signing.yaml \
    annotated-policy.wasm | jq -r ".patch | @base64d"'

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*ghcr.io/kubewarden/tests/pod-privileged:v0.2.1@sha256:db48aecd83c2826eba154a84c4fbabe0977f96b3360b4c6098578eae5c2d2882.*') -ne 0 ]
}

@test "Keyless verification with wrong subject" {
  run kwctl run \
    --request-path test_data/pod_creation_signed_with_keyless_mode.json \
    --settings-path test_data/settings-keyless-signing-wrong-subject.yaml \
    annotated-policy.wasm

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*is not accepted.*subject: !equal kubewarden@cncf.io.*') -ne 0 ]
  [ $(expr "$output" : '.*subject: !equal kubewarden@cncf.io.*') -ne 0 ]
}

