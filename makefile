build: src

src: sources.nim
	nim c -o:$@ sources.nim

check:
	nimble check
	find . -name '*.sh' -exec shellcheck {} \;
	find . -name '*.md' \
		-exec aspell --dont-backup --personal ./.dict.pws check {} \; \
		-exec markdownlint --stdin \;

format:
	find . -name '*.sh' -exec shfmt -w {} \;

doc:
	nim doc --project sources.nim

clean:
	git clean -fX

pre-commit: format check
