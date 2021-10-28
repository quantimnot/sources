version     = "0.1.0"
author      = "quantimnot"
description = "Cross-platform build tool."
license     = "MIT"
srcDir      = "."
installExt  = @["nim"]
namedBin    = {"sources": "src"}.toTable()

requires "base32"
requires "yaml"
requires "cligen"
requires "nimcrypto"
requires "mustache"

requires "iri"
requires "platforms"
requires "keys"
requires "packages"
