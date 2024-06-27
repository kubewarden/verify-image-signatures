.PHONY: ca
ca: ca.pem

ca.pem: ca.json
	@tput setaf 1
	@echo Generate root CA
	@tput sgr0
	cfssl gencert -initca ca.json | cfssljson -bare ca

.PHONY: sunlight
sunlight: sunlight.pem

sunlight.pem: sunlight.json ca.pem cfssl.json
	@tput setaf 1
	@echo Generate sunlight certificate
	@tput sgr0
	cfssl gencert -ca ca.pem \
		-ca-key ca-key.pem \
		-config cfssl.json \
		-profile=sunlight sunlight.json \
		| cfssljson -bare sunlight

.PHONY: intermediate-ca
intermediate-ca: intermediate_ca.pem

intermediate_ca.pem: ca.pem intermediate-ca.json cfssl.json
	@tput setaf 1
	@echo Generate intermediate CA
	@tput sgr0
	cfssl gencert -initca intermediate-ca.json | cfssljson -bare intermediate_ca
	cfssl sign -ca ca.pem \
		-ca-key ca-key.pem \
		-config cfssl.json \
		-profile intermediate_ca intermediate_ca.csr \
		| cfssljson -bare intermediate_ca

.PHONY: user
user: user-1-sigstore-key.pem

user-1-sigstore-key.pem: intermediate_ca.pem user-1.json cfssl.json
	@tput setaf 1
	@echo Generate user certificate
	@tput sgr0
	cfssl gencert -ca intermediate_ca.pem \
		-ca-key intermediate_ca-key.pem \
		-config cfssl.json \
		-profile=sigstore user-1.json \
		| cfssljson -bare user-1-sigstore

.PHONY: user-ctl
user-ctl: user-ctl-sigstore-key.pem

user-ctl-sigstore-key.pem: intermediate_ca.pem user-1.json cfssl.json
	@tput setaf 1
	@echo Generate user certificate with certificate transparency log signed by local instance of sunlight
	@tput sgr0
	cfssl gencert -ca intermediate_ca.pem \
		-ca-key intermediate_ca-key.pem \
		-config cfssl.json \
		-profile=sigstore-with-sunlight user-1.json \
		| cfssljson -bare user-ctl-sigstore

.PHONY: cosign-import
cosign-import: import-cosign.key

import-cosign.key: user-1-sigstore-key.pem
	@tput setaf 1
	@echo Importing certificate into cosign
	@tput sgr0
	rm -f import-cosign.key import-cosign.pub
	COSIGN_PASSWORD="" cosign import-key-pair --key user-1-sigstore-key.pem

.PHONY: bundle
bundle: bundle.pem

bundle.pem: intermediate_ca.pem ca.pem
	@tput setaf 1
	@echo Preparing bundle
	@tput sgr0
	cat intermediate_ca.pem ca.pem > bundle.pem

.PHONY: sign
sign: import-cosign.key bundle.pem
	@if [ -z "$(IMAGE)" ]; then \
		echo Specify the image to be signed via IMAGE='img' make sign; \
		exit 1;\
	else \
		tput setaf 1; \
		echo Signing $(IMAGE); \
		tput sgr0; \
	fi
	COSIGN_PASSWORD="" cosign sign \
		--key import-cosign.key \
		--certificate user-1-sigstore.pem \
		--certificate-chain bundle.pem \
		$(IMAGE)

.PHONY: sign-rekor
sign-rekor: import-cosign.key bundle.pem
	@if [ -z "$(IMAGE)" ]; then \
		echo Specify the image to be signed via IMAGE='img' make sign; \
		exit 1;\
	else \
		tput setaf 1; \
		echo Signing $(IMAGE); \
		tput sgr0; \
	fi
	COSIGN_PASSWORD="" COSIGN_EXPERIMENTAL=1 cosign sign \
		--key import-cosign.key \
		--certificate user-1-sigstore.pem \
		--certificate-chain bundle.pem \
		$(IMAGE)

.PHONY: verify
verify: bundle.pem
	@if [ -z "$(IMAGE)" ]; then \
		echo Specify the image to be verified via IMAGE='img' make verify; \
		exit 1;\
	else \
		tput setaf 1; \
		echo Verifying $(IMAGE); \
		tput sgr0; \
	fi
	cosign verify \
		--certificate user-1-sigstore.pem \
		--certificate-chain bundle.pem \
		$(IMAGE)

.PHONY: clean
clean:
	rm -f ca.csr ca-key.pem ca.pem
	rm -f intermediate_ca.csr intermediate_ca-key.pem intermediate_ca.pem
	rm -f sunlight.csr sunlight-key.pem sunlight.pem
	rm -f user-1-sigstore.csr user-1-sigstore-key.pem user-1-sigstore.pem
	rm -f user-ctl-sigstore.csr user-ctl-sigstore-key.pem user-ctl-sigstore.pem
	rm -f import-cosign.key import-cosign.pub
	rm -f bundle.pem
