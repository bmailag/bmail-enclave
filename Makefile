# Reproducible build of all four bmail enclaves. The flags here exactly
# match the GitLab CI build:enclave:* jobs that produce the binaries
# bmail.ag is running, so a clean rebuild on the same EGo version
# (currently 1.8.1) yields byte-identical MRENCLAVE measurements.

EGO_VERSION  := 1.8.1
ENCLAVES     := gateway smtp-inbound smtp-outbound payment keystore
# SGX2 "super" variants reuse the same Go binary but ship a different
# EGo JSON config (larger heap sized for the 64 GB EPC on the prod
# super-server). The MRENCLAVE differs because heapSize is hashed
# into the measurement. gateway and smtp-inbound are the only enclaves
# whose super variants run in production; the others use the regular
# small-heap config on every host.
SUPER_ENCLAVES := gateway-super smtp-inbound-super
BUILD_DIR    := build
GOFLAGS      := -tags ego -trimpath -buildvcs=false -ldflags=-s -w -buildid=

# A throwaway signing key used only because `ego sign` needs one to
# produce a SIGSTRUCT. MRENCLAVE does not include MRSIGNER, so the
# signing key has zero effect on the measurement we care about. The
# real production key lives off-line at VP.net and is never published.
SIGNING_KEY := private.pem

.PHONY: all clean check $(ENCLAVES) $(SUPER_ENCLAVES)

all: $(ENCLAVES) $(SUPER_ENCLAVES)

# Super variants do their own ego-go build rather than reusing the
# regular target's binary — `ego sign` modifies the binary in place,
# so a copy of the post-signed regular binary would get double-signed
# and produce a different MRENCLAVE than a clean rebuild. The source
# is byte-deterministic, so a second ego-go build adds ~15 seconds
# but produces the same content as the first.

# Each enclave: build the Go binary with deterministic flags, sign it
# with the throwaway key, extract MRENCLAVE, compare to the checked-in
# expected value, and print whether the measurements agree.
$(ENCLAVES):
	@echo ">>> $@"
	@mkdir -p $(BUILD_DIR)
	@if [ ! -f $(SIGNING_KEY) ]; then \
		echo "Generating throwaway signing key (only affects MRSIGNER, not MRENCLAVE)..." ; \
		openssl genrsa -out $(SIGNING_KEY) -3 3072 ; \
	fi
	CGO_ENABLED=1 ego-go build -tags ego -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o $(BUILD_DIR)/$@ ./cmd/$@
	cp enclave/$@.json $(BUILD_DIR)/$@.json
	cp $(SIGNING_KEY) $(BUILD_DIR)/private.pem
	cd $(BUILD_DIR) && ego sign $@.json
	@MRE=$$(ego uniqueid $(BUILD_DIR)/$@) ; \
	  EXPECTED=$$(tr -d '[:space:]' < enclave/mrenclaves/$@.mrenclave) ; \
	  if [ "$$MRE" = "$$EXPECTED" ]; then \
	    echo "    $@: MRENCLAVE OK ($$MRE)" ; \
	  elif [ "$@" = "keystore" ]; then \
	    echo "    $@: MRENCLAVE DRIFT — DEFERRED (ADR-008)" ; \
	    echo "      pinned (production-running, in release notes): $$EXPECTED" ; \
	    echo "      built (this rebuild from current source):      $$MRE" ; \
	    echo "      The keystore enclave seals state under MRENCLAVE-Unique," ; \
	    echo "      so a freshly-built binary cannot unseal what the running" ; \
	    echo "      one wrote. Production stays on the pinned MRENCLAVE until" ; \
	    echo "      the export/import migration tool ships (see ADR-008 in" ; \
	    echo "      bmail.git/docs/decisions/008-keystore-mrenclave-migration.md)." ; \
	  else \
	    echo "    $@: MRENCLAVE MISMATCH" ; \
	    echo "      expected: $$EXPECTED" ; \
	    echo "      built:    $$MRE" ; \
	    exit 1 ; \
	  fi

# Super variant build: matches the production CI pattern in
# .gitlab-ci.yml's build:enclave:gateway:super job. Builds in a
# private subdirectory ($BUILD_DIR/super-<base>/) so the .super.json's
# "exe": "<base>" field finds its binary unmodified, then copies the
# signed result up to $BUILD_DIR/<base>-super for the workflow's
# release-asset upload to find. Independent ego-go build (not a copy
# of the regular target's already-signed binary).
$(SUPER_ENCLAVES):
	@echo ">>> $@ (SGX2 super variant)"
	@base=$$(echo $@ | sed 's/-super$$//') ; \
	  mkdir -p $(BUILD_DIR)/super-$$base ; \
	  CGO_ENABLED=1 ego-go build -tags ego -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o $(BUILD_DIR)/super-$$base/$$base ./cmd/$$base ; \
	  cp enclave/$$base.super.json $(BUILD_DIR)/super-$$base/$$base.json ; \
	  cp $(SIGNING_KEY) $(BUILD_DIR)/super-$$base/private.pem ; \
	  (cd $(BUILD_DIR)/super-$$base && ego sign $$base.json) ; \
	  cp $(BUILD_DIR)/super-$$base/$$base $(BUILD_DIR)/$@
	@MRE=$$(ego uniqueid $(BUILD_DIR)/$@) ; \
	  base=$$(echo $@ | sed 's/-super$$//') ; \
	  EXPECTED=$$(tr -d '[:space:]' < enclave/mrenclaves/$$base.super.mrenclave) ; \
	  if [ "$$MRE" = "$$EXPECTED" ]; then \
	    echo "    $@: MRENCLAVE OK ($$MRE)" ; \
	  else \
	    echo "    $@: MRENCLAVE MISMATCH" ; \
	    echo "      expected: $$EXPECTED" ; \
	    echo "      built:    $$MRE" ; \
	    exit 1 ; \
	  fi

# Verify all checked-in MRENCLAVE values match the freshly-rebuilt ones.
check: all
	@echo "All MRENCLAVE measurements match expected values."

clean:
	rm -rf $(BUILD_DIR) $(SIGNING_KEY)
