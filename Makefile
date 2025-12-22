.PHONY: help install test clean lint format run

help:
	@echo "Available targets:"
	@echo "  make install  - Install dependencies"
	@echo "  make test     - Run tests"
	@echo "  make lint     - Run linters"
	@echo "  make format   - Format code"
	@echo "  make clean    - Clean build artifacts"
	@echo "  make run      - Run main script"

install:
	pip install -r requirements.txt
	pip install -e .

test:
	python -m pytest tests/ -v

lint:
	pre-commit run --all-files

format:
	black cryptogenesis/ tests/ main.py
	isort cryptogenesis/ tests/ main.py

clean:
	find . -type d -name __pycache__ -exec rm -r {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -r {} +
	rm -rf build/ dist/

run:
	python main.py
