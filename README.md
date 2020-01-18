# Findings Toolkit

A simple tool to make it easier to interact with a standard
finding format [Open Finding Format](https://github.com/owasp/off).

## Installation

`go get github.com/jemurai/fkit`

## Working With FKit

### New 

New - this creates a finding and drops it in a json array:

```sh
fkit new --name "Finding Name" --description "Finding Description" --detail "Finding detail" --severity "High" --fingerprint "xyz" --source "File" --location "Line 50" --cvss 9.3 --tag "abc" --tag "def" --cwe https://cwe.mitre.org/data/definitions/134.html --reference https://github.com/owasp/off > demofinding.json
```

### Read 

Reading a file with an array of findings:

```sh
fkit read --infile demofindings.json
```

## Pushing Issues To GitHub

We can push issues to GitHub by supplying the file of findings, a repo, an owner and a valid personal access token:

```sh
go run main.go report --debug --file ../crush/newfindings.json --github-repo fkit --github-token <token> --github-owner jemurai
```

This is useful in conjunction with other tools that produce findings.
