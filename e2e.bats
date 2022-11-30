#!/usr/bin/env bats

@test "Accept a valid signature" {
  run kwctl run  --request-path test_data/pod_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature" {
  run kwctl run  --request-path test_data/pod_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*"message":"Pod invalid-pod-name is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Mutate Pod definition" {
  # Need to run the command inside of `bash -c` because of a bats
  # limitation: https://bats-core.readthedocs.io/en/stable/gotchas.html?highlight=pipe#my-piped-command-does-not-work-under-run

  run bash -c 'kwctl run \
    --request-path test_data/pod_creation_signed.json \
    --settings-path test_data/settings-mutation-enabled.yaml \
    annotated-policy.wasm | jq -r ".patch | @base64d"'
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*ghcr.io/kubewarden/test-verify-image-signatures:signed@sha256:1d9d3da4c60d27b77bb96bba738319c1c4424853fdd10f65982f9f2ca2422a72.*') -ne 0 ]
}

@test "Do not mutate Pod definition" {
  # Need to run the command inside of `bash -c` because of a bats
  # limitation: https://bats-core.readthedocs.io/en/stable/gotchas.html?highlight=pipe#my-piped-command-does-not-work-under-run

  run bash -c 'kwctl run \
    --request-path test_data/pod_creation_signed.json \
    --settings-path test_data/settings-mutation-disabled.yaml \
    annotated-policy.wasm | jq -r ".patch"'
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : 'null') -ne 0 ]
}

@test "Accept a valid signature in a Deployment" {
  run kwctl run  --request-path test_data/deployment_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature in a Deployment" {
  run kwctl run  --request-path test_data/deployment_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Accept a valid signature in a StatefulSet" {
  run kwctl run  --request-path test_data/statefulset_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature in a StatefulSet" {
  run kwctl run  --request-path test_data/statefulset_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Accept a valid signature in a ReplicaSet" {
  run kwctl run  --request-path test_data/replicaset_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature in a ReplicaSet" {
  run kwctl run  --request-path test_data/replicaset_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Accept a valid signature in a ReplicationController" {
  run kwctl run  --request-path test_data/replicationcontroller_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature in a ReplicationController" {
  run kwctl run  --request-path test_data/replicationcontroller_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Accept a valid signature in a Job" {
  run kwctl run  --request-path test_data/job_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature in a Job" {
  run kwctl run  --request-path test_data/job_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Accept a valid signature in a CronJob" {
  run kwctl run  --request-path test_data/cronjob_creation_signed.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
}

@test "Reject invalid signature in a CronJob" {
  run kwctl run  --request-path test_data/cronjob_creation_unsigned.json --settings-path test_data/settings-mutation-enabled.yaml annotated-policy.wasm
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
  [ $(expr "$output" : '.*is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
}

@test "Certificate verification with Rekor enabled" {
  # Need to run the command inside of `bash -c` because of a bats
  # limitation: https://bats-core.readthedocs.io/en/stable/gotchas.html?highlight=pipe#my-piped-command-does-not-work-under-run

  run bash -c 'kwctl run \
    --request-path test_data/pod_creation_signed_with_certificate.json \
    --settings-path test_data/settings-pod_signed_with_cert_and_rekor.yaml \
    annotated-policy.wasm | jq -r ".patch | @base64d"'
  [ "$status" -eq 0 ]
  echo "$output"
  [ $(expr "$output" : '.*ghcr.io/kubewarden/tests/pod-privileged:v0.2.1@sha256:db48aecd83c2826eba154a84c4fbabe0977f96b3360b4c6098578eae5c2d2882.*') -ne 0 ]
}

