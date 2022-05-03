# Kubewarden policy verify-image-signatures

## Description

This policy validates Sigstore signatures for containers, init container and ephemeral container that match the name provided
in the `image` settings field. It will reject the Pod if any validation fails.
If all signature validation pass or there is no container that matches the image name, the Pod will be accepted.

This policy also mutates matching images to add the image digest, therefore the version of the deployed image can't change. 
This mutation can be disabled by setting `modifyImagesWithDigest` to `false`.

See the [Secure Supply Chain docs in Kubewarden](https://docs.kubewarden.io/distributing-policies/secure-supply-chain.html) for more info.

## Settings

The policy takes a list of signatures. A signature can be of two types: public key or keyless. Each signature
has an `image` field which will be used to select the matching containers in the pod that will be evaluated.
`image` supports wildcard. For example, `ghcr.io/kubewarden/*` will match all images from the kubewarden ghcr repo.

Example:

```yaml
modifyImagesWithDigest: true #optional. default is true
signatures:
  - image: "*"
    pubKeys: 
      - ....
    annotations: #optional
      env: prod
  - image: "ghcr.io/kubewarden/*" 
    keyless:
      - issuer: "https://token.actions.githubusercontent.com"
        subject: "kubewarden"
    annotations: #optional
      env: prod
```

This policy will validate all images with the public keys provided, and images whose name matches `ghcr.io/kubewarden/*` with the keyless provided.

## License

```
Copyright (C) 2022 Raul Cabello Martin <raul.cabello@suse.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
