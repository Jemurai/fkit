# Findings Toolkit

A simple tool to make it easier to interact with a standard
finding format.

## Usage

`fkit new --directory /your/code/here`

## Installation

`go get github.com/jemurai/fkit`

## Working With FKit

New - this creates a finding and drops it in a json array:

```sh
go run main.go --debug --name "Finding Name" --description "Finding Description" --detail "Finding detail" --severity "High" --fingerprint "xyz" --source "File" --location "Line 50" --cvss 9.3 new > demofinding.json
```

Reading a file with an array of findings:

```sh
go run main.go --debug --file demofinding.json read
```