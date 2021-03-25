# Security Hub Collector

## Description

This tool pulls findings from AWS Security Hub and outputs them for
consumption by visualization tools.

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
  -o, --output=  File to direct output to.
  -p, --profile= The AWS profile to use. [$AWS_PROFILE]
  -r, --region=  The AWS region to use. [$AWS_REGION]

Help Options:
  -h, --help     Show this help message

```

## Examples

Run the command like this:

```sh
security-hub-collector -o output.csv
```
