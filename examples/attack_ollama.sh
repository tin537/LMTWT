#!/bin/bash

# Sample script to attack Ollama API using the enhanced hacker mode
# This demonstrates the conversation history analysis capability

# Run the attack in interactive mode with hacker mode enabled
../run.sh --attacker gemini \
    --target external-api \
    --target-config examples/ollama_target.json \
    --mode interactive \
    --hacker-mode

echo "Attack session completed." 