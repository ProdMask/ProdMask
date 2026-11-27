## What this changes

## How it's tested

- [ ] `gofmt -l .`, `go vet ./...` and `go test ./...` pass
- [ ] Golden files updated with `go test ./pkg/scan -update`, `go test ./pkg/report -update` and `go test ./pkg/cli -run TestScanDumpGoldens -update`, if findings or reports changed, and the diff reviewed
- [ ] No real data anywhere, and anything shaped like an API key is built from pieces at run time
