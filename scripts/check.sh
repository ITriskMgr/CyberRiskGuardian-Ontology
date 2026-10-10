#!/usr/bin/env bash
# Build and check the CyberRiskGuardian Ontology.
# Requires: Python 3 with rdflib, Java 11+, ROBOT (robot.jar; set ROBOT_JAR or put robot on PATH).
set -u
cd "$(dirname "$0")/.."
ROBOT=${ROBOT_JAR:+java ${ROBOT_JAVA_ARGS:--Xmx6g} -jar $ROBOT_JAR}
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

echo "7. SKOS vocabularies"
python3 scripts/check_vocab.py || fail=1

echo "8. CRG bridge (MediBec regression: 84,491 estimated, 41,104 residual)"
if [ -n "${CRG_CALC:-}" ]; then
  python3 pipeline/crg/crg2rdf.py tests/crg/medibec30.json --crg-calc "$CRG_CALC" --base https://w3id.org/crgo/data/medibec/ \
    --out tests/crg/medibec30.ttl --jsonld tests/crg/medibec30.jsonld > /dev/null || fail=1
fi
python3 tests/crg/check_roundtrip.py | sed 's/^/   /' || fail=1
if $ROBOT reason --catalog tests/crg/catalog-v001.xml --input tests/crg/medibec30.ttl --reasoner HermiT --output build/medibec-inferred.ttl > build/medibec-reason.log 2>&1; then
  echo "   medibec30: consistent"; else echo "   medibec30: INCONSISTENT (see build/medibec-reason.log)"; fail=1; fi

if [ "${WITH_LIBRARY:-0}" = 1 ]; then
  echo "9. Full ontology with scenario library and vocabularies (slow)"
  $ROBOT merge --catalog ontology/catalog-v001.xml --input ontology/crgo-full.ttl --output build/crgo-full-merged.ttl > build/full-merge.log 2>&1 || { echo "   full merge FAILED"; fail=1; }
  if $ROBOT validate-profile --input build/crgo-full-merged.ttl --profile DL --output build/full-profile.txt > /dev/null 2>&1; then
    echo "   crgo-full (modules + library + vocabularies): in OWL 2 DL"; else echo "   crgo-full: NOT in OWL 2 DL (see build/full-profile.txt)"; fail=1; fi
  if $ROBOT reason --input build/crgo-full-merged.ttl --reasoner HermiT --equivalent-classes-allowed none --output build/full-inferred.ttl > build/full-reason.log 2>&1; then
    echo "   crgo-full: consistent, no unsatisfiable classes"; else echo "   crgo-full: FAILED (see build/full-reason.log)"; fail=1; fi
fi

if [ "${WITH_LIBRARY:-0}" = 1 ]; then
  echo "10. SHACL shapes (data and negative tests)"
  python3 src/build_shapes.py > /dev/null && python3 scripts/check_shacl.py || fail=1
  echo "11. Pitfall scan (OOPS! catalogue, local)"
  python3 scripts/check_pitfalls.py > build/pitfalls.log || { cat build/pitfalls.log; fail=1; }
  grep -c "CRITICAL" build/pitfalls.log > /dev/null && { echo "   critical pitfalls found"; fail=1; } || echo "   no critical pitfalls (details: build/pitfalls.md)"
  echo "12. Query store, competency questions and identification interface"
  python3 pipeline/query/store.py | sed 's/^/   /' || fail=1
  python3 tests/cq/run_cq.py | tail -1 | sed 's/^/   /'; [ ${PIPESTATUS[0]} = 0 ] || fail=1
  python3 tests/identify/test_identify.py | tail -1 || fail=1
fi

echo "13. w3id.org redirect rules"
python3 scripts/check_w3id.py | tail -1 || fail=1

[ $fail = 0 ] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit $fail
