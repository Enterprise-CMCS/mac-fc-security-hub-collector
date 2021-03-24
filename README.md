# Truss CLI Template

This repository is meant to be a template repo to set up new CLIs with our general format. Everywhere
the tool or binary is listed in this repo the name `my-cli-tool` will be used for search and replace
purposes.

## Creating a new CLI repo

1. Clone this rep, renaming appropriately.
1. Write your golang code in the `main.go` file.
1. Run `go mod init github.com/trussworks/my-cli-tool
1. Run `go mod tidy` to update the `go.mod` and `go.sum` files
1. Build your tool with `go build .`

## Actual readme below  - Delete above here

# my-binary

## Description

Please include a description of the CLI tool here

## Installation

Include installation instructions with an example

```sh
brew tap trussworks/tap
brew install my-cli-tool
```

## Usage

Include usage information here:

```sh
TBD
```

## Examples

Run the command like this:

```sh
TBD
```
