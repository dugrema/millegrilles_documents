#!/usr/bin/env bash

echo "Build target rust"
cargo b --release --package millegrilles_documents --bin millegrilles_documents
