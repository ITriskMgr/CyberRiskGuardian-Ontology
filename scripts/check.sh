#!/usr/bin/env bash
# Build and check the CyberRiskGuardian Ontology.
# Requires: Python 3 with rdflib, Java 11+, ROBOT (robot.jar; set ROBOT_JAR or put robot on PATH).
set -u
cd "$(dirname "$0")/.."
ROBOT=${ROBOT_JAR:+java -jar $ROBOT_JAR}
ROBOT=${ROBOT:-robot}
mkdir -p build
fail=0

echo "1. Generate modules from the specification"
python3 src/build.py || exit 1
python3 tests/make_fixtures.py > /dev/null || exit 1

echo "2. Merge with imports (BFO-2020 core, CCO 2.2 slice)"
$ROBOT merge --catalog ontology/catalog-v001.xml --input ontology/crgo.ttl --output build/crgo-merged.ttl > build/merge.log 2>&1 || { echo "   merge FAILED"; exit 1; }

echo "3. Reason: consistency and unsatisfiable classes"
for r in HermiT ELK; do
  if $ROBOT reason --input build/crgo-merged.ttl --reasoner $r --equivalent-classes-allowed none --output build/inferred-$r.ttl > build/reason-$r.log 2>&1; then
    echo "   $r: consistent, no unsatisfiable classes"
  else
    echo "   $r: FAILED (see build/reason-$r.log)"; fail=1
  fi
done

echo "4. OWL 2 DL profile (with imports)"
if $ROBOT validate-profile --input build/crgo-merged.ttl --profile DL --output build/profile-DL.txt > /dev/null 2>&1; then
  echo "   in OWL 2 DL"; else echo "   NOT in OWL 2 DL (see build/profile-DL.txt)"; fail=1; fi

echo "5. Test fixtures (instance data)"
for f in tests/fixtures/*.ttl; do
  n=$(basename "$f" .ttl)
  if $ROBOT reason --catalog tests/fixtures/catalog-v001.xml --input "$f" --reasoner HermiT --output build/out-$n.ttl > build/fx-$n.log 2>&1; then ok=consistent; else ok=inconsistent; fi
  case "$n" in
    neg-*) [ "$ok" = inconsistent ] && echo "   $n: inconsistent, as expected" || { echo "   $n: SHOULD BE INCONSISTENT"; fail=1; } ;;
    *)     [ "$ok" = consistent ] && echo "   $n: consistent, as expected" || { echo "   $n: SHOULD BE CONSISTENT"; fail=1; } ;;
  esac
done

echo "6. Governance metadata and labels"
python3 scripts/check_metadata.py || fail=1
python3 scripts/check_modules.py || fail=1

[ $fail = 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit $fail
