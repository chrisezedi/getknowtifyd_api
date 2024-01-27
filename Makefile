.PHONY: test-coverage

test-coverage:
	pytest --cov=core && coverage html