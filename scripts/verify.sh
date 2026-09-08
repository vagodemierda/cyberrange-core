#!/usr/bin/env bash

set -e

cd "$(dirname "$0")/.."

echo
echo "============================================================"
echo " CYBERRANGECORE - VALIDACIÓN COMPLETA"
echo "============================================================"
echo

echo "[1/3] Smoke test"
python tests/smoke_test.py

echo
echo "[2/3] Functional test"
python tests/functional_test.py

echo
echo "[3/3] End-to-end acceptance test"
python tests/e2e_test.py

echo
echo "============================================================"
echo " RESULTADO: CYBERRANGECORE VALIDACIÓN COMPLETA APROBADA"
echo "============================================================"
echo
