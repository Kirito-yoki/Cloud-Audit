.PHONY: all scan report organize

all: scan report organize

scan:
	@echo "==> Running Prowler scan against CIS 3.0 AWS Benchmarks..."
	-prowler aws --compliance cis_3.0_aws -M json-asff --ignore-exit-code-3

report:
	@echo "==> Generating custom HTML report..."
	python3 generate_html.py

organize:
	@echo "==> Organizing results into a timestamped folder..."
	python3 organize_output.py