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

# Super variants depend on their non-super counterparts so the Go
# binary is built once and reused.
gateway-super: gateway
smtp-inbound-super: smtp-inbound

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
	  else \
	    echo "    $@: MRENCLAVE MISMATCH" ; \
	    echo "      expected: $$EXPECTED" ; \
	    echo "      built:    $$MRE" ; \
	    exit 1 ; \
	  fi

# Super variant build: copy the regular binary, swap in the .super
# JSON, re-sign, assert MRENCLAVE matches the .super.mrenclave file.
$(SUPER_ENCLAVES):
	@echo ">>> $@ (SGX2 super variant)"
	@base=$$(echo $@ | sed 's/-super$$//') ; \
	  cp $(BUILD_DIR)/$$base $(BUILD_DIR)/$@ ; \
	  cp enclave/$$base.super.json $(BUILD_DIR)/$@.json
	cp $(SIGNING_KEY) $(BUILD_DIR)/private.pem
	cd $(BUILD_DIR) && ego sign $@.json
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
