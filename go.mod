module github.com/Arequ/mission-control

go 1.22

require (
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.7.2
	gopkg.in/yaml.v3 v3.0.1
)

// pgx's module graph pulls kr/pretty, which imports go-internal/fmtsort.
// Current go-internal releases require Go 1.25, so stay on a 1.22-compatible pin.
exclude github.com/rogpeppe/go-internal v1.16.0

replace github.com/rogpeppe/go-internal => github.com/rogpeppe/go-internal v1.13.1

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)
