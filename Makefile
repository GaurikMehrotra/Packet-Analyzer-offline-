PYTHON ?= .venv/bin/python
TShark ?= tshark
export MPLCONFIGDIR ?= $(CURDIR)/.cache/matplotlib
export XDG_CACHE_HOME ?= $(CURDIR)/.cache

.PHONY: setup fixtures check test oracle fuzz bench detect-eval smoke wheel

setup:
	bash scripts/bootstrap.sh

fixtures:
	$(PYTHON) fixtures/generate_fixtures.py

check:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest -m "not oracle" -q

oracle:
	PCAPLENS_TSHARK=$(TShark) $(PYTHON) -m pytest -m oracle -q
	$(PYTHON) eval/oracle_tshark.py fixtures/protocols-le-us.pcap fixtures/reassembly.pcap fixtures/tls.pcap --tshark $(TShark)

fuzz:
	$(PYTHON) eval/fuzz.py --cases 10000 --seed 20250317

bench:
	$(PYTHON) eval/bench.py --sizes 1000 10000 50000 --repeats 3

detect-eval:
	$(PYTHON) eval/detect_eval.py --seed 20250317

smoke:
	.venv/bin/pcaplens summary fixtures/protocols-le-us.pcap --checksum

wheel:
	$(PYTHON) -m pip wheel --no-deps --no-build-isolation . -w dist
