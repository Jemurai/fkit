# Findings Toolkit

A simple tool and library to make it easier to interact with a standard
finding format [Open Finding Format](https://github.com/owasp/off).

## Installation

`go get github.com/jemurai/fkit`

## Working With FKit

### New 

New - this creates a finding and drops it in a json array:

```sh
fkit new --name "Finding Name" \
         --description "Finding Description" \
         --detail "Finding detail" \
         --severity "High" \
         --fingerprint "xyz" \
         --source "File" \
         --location "Line 50" \
         --cvss 9.3 \
         --tag "abc" \
         --tag "def" \
         --cwe https://cwe.mitre.org/data/definitions/134.html \
         --reference https://github.com/owasp/off \
         > demofinding.json
```

New Options - see the above.  tag, cwe and reference can appear many times.

### Read 

Reading a file with an array of findings:

```sh
fkit read --infile demofindings.json
```

Read options:

- `--infile <file>`
- `--intype fkit|owaspdepcheck` - read in JSON from Dependency Check
- `--outtype csv|json` - output in json or CSV

### Compare

We can compare files with findings.

```sh
./fkit compare --fromfile demofindings.json --tofile demofinding.json
```

Compare options:

- `--fromfile <file>`
- `--tofile <otherfile>`

### Global Options

- `--debug` Enables debug messages.
- `--help`  Prints help information.

### Working with the Library

You can interact with the Finding directly.

```go
finding := finding.Finding{
		Name:        viper.GetString("name"),
		Description: viper.GetString("description"),
		Detail:      viper.GetString("detail"),
		Severity:    viper.GetString("severity"),
		Confidence:  viper.GetString("confidence"),
		Fingerprint: viper.GetString("fingerprint"),
		Timestamp:   time.Now(),
		Source:      viper.GetString("source"),
		Location:    viper.GetString("location"),
		Cvss:        viper.GetFloat64("cvss"),
		References:  viper.GetStringSlice("reference"),
		Cwes:        viper.GetStringSlice("cwe"),
		Tags:        viper.GetStringSlice("tag"),
	}
```

Useful methods include: 

* BuildFindingsFromFile 
    * `func BuildFindingsFromFile(file string) []finding.Finding `
* finding.GetDetailString
* Compare
    *  `func CompareFiles(fromfile string, tofile string) []finding.Finding`
    *  `func CompareFileAndArray(fromfile string, newFindings []finding.Finding) []finding.Finding`
    *  `func Compare(oldFindings []finding.Finding, findings []finding.Finding) []finding.Finding`


## Pushing Issues To GitHub

We can push issues to GitHub by supplying the file of findings, a repo, an owner and a valid personal access token:

```sh
fkit report --debug --file ../crush/newfindings.json --github-repo fkit --github-token <token> --github-owner jemurai
```

This is useful in conjunction with other tools that produce findings.
