#!/usr/bin/env bash
# Fetch the public machine-readable sources used by pipeline/vocab/build_vocab.py into data/raw/.
# The 2023 scenario library (combined_file.xlsx) is not public; copy it into data/raw/ by hand.
set -eu
cd "$(dirname "$0")/.."
mkdir -p data/raw
OSCAL=https://raw.githubusercontent.com/usnistgov/oscal-content/78650f02ad9321bb7b817846f8fbd4f2bcd620de
curl -fsSL -o data/raw/NIST_CSF_v2.0_catalog.json "$OSCAL/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json"
curl -fsSL -o data/raw/NIST_SP-800-53_rev5_catalog.json "$OSCAL/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
curl -fsSL -o data/raw/enterprise-attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json
echo "sources in data/raw/"
