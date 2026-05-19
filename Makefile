.PHONY: help build test ci run menu tui interview campaign policy corpus stress list singlepass supervisor matrix emit-wasm report-json report-md report-sarif report-interview report-campaign install-check install-local

help:
	@printf '%s\n' \
	  'targets:' \
	  '  build             cargo build --release' \
	  '  test              cargo test' \
	  '  ci                local CI parity checks' \
	  '  run               run full corpus' \
	  '  menu              interactive security console with session history and charts' \
	  '  tui               live interview cockpit' \
	  '  interview         non-animated interview flow' \
	  '  campaign          defensive adversary-emulation campaign' \
	  '  policy            run interview flow with policy.example.toml' \
	  '  corpus            run example external corpus' \
	  '  stress            repeat full corpus 1000 times' \
	  '  singlepass        run full corpus under Singlepass backend' \
	  '  supervisor        prove process supervisor kills non-cooperative guest' \
	  '  list              list hostile guest cases' \
	  '  emit-wasm         compile WAT guests into target/guests-wasm' \
	  '  matrix            optional wasmer CLI backend matrix' \
	  '  report-md         write ABI Markdown report' \
	  '  report-json       write resource JSON report' \
	  '  report-sarif      write CI-native SARIF report' \
	  '  report-interview  write curated interview Markdown report' \
	  '  report-campaign   write adversary-emulation Markdown report' \
	  '  install-check     verify install path via curl bootstrap' \
	  '  install-local     install release binary into target/install-bin'

build:
	cargo build --release

test:
	cargo test

ci:
	cargo fmt --check
	cargo test
	cargo run --release -- --profile all --summary-only --no-color
	cargo run --release -- --profile all --backend singlepass --summary-only --no-color
	cargo run --release -- --case non_cooperative_loop --isolate process --timeout-ms 100 --no-color
	cargo run --release -- --policy policy.example.toml --profile all --summary-only --no-color
	cargo run --release -- --corpus examples/external-corpus --no-color
	cargo run --release -- --campaign --summary-only --no-color
	cargo run --release -- --profile all --format sarif --report target/wasmer-harness.sarif

run:
	cargo run --release

menu:
	cargo run --release -- --menu

tui:
	cargo run --release -- --interview --tui

interview:
	cargo run --release -- --interview --no-color

campaign:
	cargo run --release -- --campaign --no-color

policy:
	cargo run --release -- --policy policy.example.toml --interview --no-color

corpus:
	cargo run --release -- --corpus examples/external-corpus --no-color

stress:
	cargo run --release -- --stress 1000 --no-color

singlepass:
	cargo run --release -- --profile all --backend singlepass --summary-only --no-color

supervisor:
	cargo run --release -- --case non_cooperative_loop --isolate process --timeout-ms 100 --no-color

list:
	cargo run -- --list

emit-wasm:
	cargo run --release -- --emit-wasm-dir target/guests-wasm

matrix:
	./scripts/wasmer-cli-matrix.sh

report-json:
	cargo run --release -- --profile resource --format json --report target/resource-report.json

report-md:
	cargo run --release -- --profile abi --format markdown --report target/abi-report.md

report-sarif:
	cargo run --release -- --profile all --format sarif --report target/wasmer-harness.sarif

report-interview:
	cargo run --release -- --profile interview --format markdown --report target/interview-report.md

report-campaign:
	cargo run --release -- --profile campaign --format markdown --report target/adversary-campaign.md

install-check:
	curl -fsSL file://$(CURDIR)/scripts/install.sh | bash -s -- --check --source-dir "$(CURDIR)"

install-local:
	curl -fsSL file://$(CURDIR)/scripts/install.sh | bash -s -- --source-dir "$(CURDIR)" --install-dir "$(CURDIR)/target/install-bin"
