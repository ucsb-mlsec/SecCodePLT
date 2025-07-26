#!/bin/bash

# Simple test runner for JUnit tests
# Usage: test-runner.sh <test_class_name>

set -e

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <test_class_name>"
    exit 1
fi

TEST_CLASS="$1"

# Download JUnit if not present
if [ ! -f "/tmp/junit-platform-console-standalone-1.9.3.jar" ]; then
    echo "Downloading JUnit 5..."
    curl -L -o /tmp/junit-platform-console-standalone-1.9.3.jar \
        https://repo1.maven.org/maven2/org/junit/platform/junit-platform-console-standalone/1.9.3/junit-platform-console-standalone-1.9.3.jar
fi

# Run the test
echo "Running test: $TEST_CLASS"
java -cp ".:/tmp/junit-platform-console-standalone-1.9.3.jar" \
    org.junit.platform.console.ConsoleLauncher \
    --select-class="$TEST_CLASS" \
    --details=verbose 