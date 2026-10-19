package vuln

// GitOpsBoundary is the only promotion path. The string is here so a test can
// fail if a handler starts calling the catalog promote API for a vulnerability.
const GitOpsBoundary = "open-pr"
