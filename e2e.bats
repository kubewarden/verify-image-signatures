#!/usr/bin/env bats

@test "Accept a valid signature" {
	run kwctl run  --request-path test_data/pod_creation_signed.json --settings-path test_data/settings.yaml annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":true.*') -ne 0 ]
 }

@test "Reject invalid signature" {
	run kwctl run  --request-path test_data/pod_creation_unsigned.json --settings-path test_data/settings.yaml annotated-policy.wasm
	[ "$status" -eq 0 ]
	echo "$output"
	[ $(expr "$output" : '.*"allowed":false.*') -ne 0 ]
	[ $(expr "$output" : '.*"message":"Pod invalid-pod-name is not accepted: verification of image ghcr.io/kubewarden/test-verify-image-signatures:unsigned failed.*') -ne 0 ]
 }
