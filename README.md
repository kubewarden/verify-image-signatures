# Kubewarden policy verify-image-signatures

## Description

This policy will validate containers, init container and ephemeral container that matches the name provided 
in the `image` settings field. It will reject the pod if any validation fails. 
If all signature validation pass or there is no container that matches the image name, the pod will be accepted.

TODO add link to sigstore doc

## Settings

The policy takes a list of signatures. A signature can be of two types: public key or keyless. Each signature
has an `image` field which will be used to select the matching containers in the pod that will be evaluated.
`image` supports wildcard. For example, `ghcr.io/kubewarden/*` will match all images from the kubewarden ghcr repo.

Example:

```yaml
signatures:
  - image: "nginx"
    pub_keys: 
      - ....
    annotations: #optional
      env: prod
  - image: "*" #matches all images
    keyless:
      - issuer: "https://token.actions.githubusercontent.com"
        subject: "kubewarden"
    annotations: #optional
      env: prod
```

## License

```
Copyright (C) 2021 Flavio Castelli <fcastelli@suse.com>

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
