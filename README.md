# FROST CLI Implementation

A command-line tool implementing the FROST (Flexible Round-Optimized Schnorr Threshold) signatures protocol.

## Features
- Generates keys for n participants with threshold t
- Creates and verifies threshold signatures
- Stores group public key for verification

## Usage
```bash
# Generate keys and create signature
cargo run -- --participants 5 --threshold 3 --output ./keys

# Keys will be stored in the specified output directory

## Next steps
# 1. Command Separation
# Split signature verification into separate CLI command
# Implement proper command handling structure
# Add proper error handling for each command

# 2. Code Architecture
# Reorganize code into modular structure
# Move CLI logic to cli.rs
# Implement proper error handling in error.rs
# Create storage abstraction in storage.rs
# Move FROST operations to crypto.rs

# 3. Testing
# Add unit tests for each module
# Add integration tests for CLI commands
# Add property-based tests for crypto operations
# Add test coverage reporting

# 4. Library Enhancement (Optional)
# Fork frost-dalek repository
# Implement to_bytes() for SecretKey type
# Add proper serialization traits
# This would of course only be for demonstration purposes, 
# as Secret Keys should not be accessible by the machine generating them

# 5. Complete CLI Implementation
# Once the above is completed, the CLI will support three main operations:

# Generate keys
# frost-cli generate --participants 5 --threshold 3 --output ./keys

# Sign message
# frost-cli sign --message "Hello, World" --output signature.json

# Verify signature
# frost-cli verify --message "Hello, World" --signature signature.json

## Improvements to the library
# Documentation:
# Although an example for a simple use case is already provided, a runnable example could be great
# Adding a flow chart / sequence diagram would also greatly improve the comprehensibility of the protocl

