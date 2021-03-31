# Security Hub Collector

## Description

This tool pulls findings from AWS Security Hub and outputs them for
consumption by visualization tools. In order to use this tool, you will
need to have valid AWS credentials in your environment (or provide a
profile for the tool to use).

## Installation

```sh
go get -u github.com/trussworks/security-hub-collector
```

## Usage

```sh
security-hub-collector is an application for retrieving Security Hub findings for visualization

Usage:
  security-hub-collector [OPTIONS]

Application Options:
  -o, --output=  File to direct output to. (default: SecurityHub-Findings.csv)
  -p, --profile= The AWS profile to use. [$AWS_PROFILE]
  -r, --region=  The AWS region to use. [$AWS_REGION]
  -m, --teammap= JSON file containing team to account mappings.

Help Options:
  -h, --help     Show this help message

```

## Examples

Run the command like this:

```sh
security-hub-collector -m teammap.json
```
