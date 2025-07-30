#!/bin/bash

# Java Patch Evaluation Script
# Usage: compile-and-test-patch.sh <test_file> <complete_java_file>

set -e

# Set JAVA_HOME environment variable
export JAVA_HOME=/usr/local/openjdk-17
export PATH="$JAVA_HOME/bin:$PATH"

# Set Maven local repository to a temporary location
export MAVEN_OPTS="-Dmaven.repo.local=/tmp/maven-repo-$$"
mkdir -p "/tmp/maven-repo-$$"

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <test_file> <complete_java_file>"
    echo "  test_file: JUnit test file"
    echo "  complete_java_file: Complete Java file (no template insertion needed)"
    exit 1
fi

TEST_FILE="$1"
JAVA_FILE="$2"
TIMEOUT_DURATION=30

# Check if files exist
for file in "$TEST_FILE" "$JAVA_FILE"; do
    if [ ! -f "$file" ]; then
        echo "Error: File $file not found"
        exit 1
    fi
done

# Create temporary working directory
WORK_DIR="/tmp/java-eval/$(date +%s)_$$"
mkdir -p "$WORK_DIR/src/main/java"
mkdir -p "$WORK_DIR/src/test/java"

# Copy pom.xml to working directory
cp /workspace/pom.xml "$WORK_DIR/"

# Copy juliet support classes to working directory  
mkdir -p "$WORK_DIR/src/main/java/juliet"
cp -r /workspace/src/main/java/juliet/support "$WORK_DIR/src/main/java/juliet/"

echo "=== Starting Java Patch Evaluation ==="
echo "Test: $TEST_FILE"
echo "Complete Java file: $JAVA_FILE"
echo "Working directory: $WORK_DIR"

# Read Java code
echo "=== Reading complete Java file ==="
JAVA_CODE=$(cat "$JAVA_FILE")
echo "Java code length: ${#JAVA_CODE} characters"

# Extract class name and package from the complete Java file
MAIN_CLASS_NAME=$(python3 -c "
import sys, re
with open(sys.argv[1], 'r') as f:
    content = f.read()
match = re.search(r'public class (\w+)', content)
print(match.group(1) if match else 'UnknownClass')
" "$JAVA_FILE")

PACKAGE_NAME=$(python3 -c "
import sys, re
with open(sys.argv[1], 'r') as f:
    content = f.read()
match = re.search(r'package\s+([^;]+);', content)
print(match.group(1) if match else 'juliet.testcases.CWE193_Off_by_One_Error')
" "$JAVA_FILE")

TEST_CLASS_NAME=$(python3 -c "
import sys, re
with open(sys.argv[1], 'r') as f:
    content = f.read()
match = re.search(r'public class (\w+)', content)
print(match.group(1) if match else 'UnknownTestClass')
" "$TEST_FILE")

echo "Main class: $MAIN_CLASS_NAME, Test class: $TEST_CLASS_NAME, Package: $PACKAGE_NAME"

# Copy complete Java file directly (no template insertion)
echo "=== Copying complete Java file ==="
cp "$JAVA_FILE" "$WORK_DIR/src/main/java/${MAIN_CLASS_NAME}.java"

# Copy test file with correct name and add package + throws Throwable
echo "Processing test file: adding package declaration and throws Throwable..."
# Add package and modify test methods to handle Throwable
python3 -c "
import sys
import re

test_file = sys.argv[1]
output_file = sys.argv[2]
package_name = sys.argv[3]

with open(test_file, 'r') as f:
    content = f.read()

# Add package declaration if missing
if not re.search(r'^package\s+', content, re.MULTILINE):
    # Also add necessary imports for juliet.support classes
    imports = ''
    if 'IO.' in content or 'IO::' in content:
        imports = 'import juliet.support.IO;\n'
    content = f'package {package_name};\n\n{imports}' + content

# Add throws Throwable to ALL methods that might need it - comprehensive approach
# 1. Handle @Test methods with multiline patterns  
content = re.sub(r'(@Test\s*\n\s*public\s+void\s+\w+\s*\([^)]*\))(\s*\{)', r'\1 throws Throwable\2', content, flags=re.MULTILINE)
# 2. Handle @Test methods on same line
content = re.sub(r'(@Test\s+public\s+void\s+\w+\s*\([^)]*\))(\s*\{)', r'\1 throws Throwable\2', content)
# 3. Handle any public void methods that look like test methods
content = re.sub(r'(public\s+void\s+test\w*\s*\([^)]*\))(?!\s*throws)(\s*\{)', r'\1 throws Throwable\2', content)
# 4. Handle private helper methods
content = re.sub(r'(private\s+[\w<>\[\],\s]+\s+\w+\s*\([^)]*\))(?!\s*throws)(\s*\{)', r'\1 throws Throwable\2', content)
# 5. Handle any other public void methods in test files (catch-all)
content = re.sub(r'(public\s+void\s+\w+\s*\([^)]*\))(?!\s*throws)(\s*\{)', r'\1 throws Throwable\2', content)

# Handle lambda expressions that call methods throwing Throwable
# Wrap lambda bodies in try-catch blocks if they contain method calls
if 'captureStdOut(() -> {' in content:
    # Find all lambda expressions and wrap their content in try-catch
    content = re.sub(
        r'(captureStdOut\(\(\) -> \{)(.*?)(\}\))',
        r'\1\n            try {\2\n            } catch (Throwable t) {\n                throw new RuntimeException(t);\n            }\3',
        content,
        flags=re.DOTALL
    )

# Fix static method calls - if test is calling ClassName.methodName(), create instance instead
# Extract class name from the test file name instead of template file
test_class_name = test_file.split('/')[-1].replace('_Test.java', '').replace('.java', '')
if f'{test_class_name}.processData' in content or f'{test_class_name}.case1' in content:
    # Add instance creation at the beginning of each test method
    content = re.sub(
        r'(@Test\s*\n?\s*public\s+void\s+\w+\s*\([^)]*\)\s*(?:throws\s+Throwable\s*)?\{)',
        rf'\1\n        {test_class_name} instance = new {test_class_name}();',
        content,
        flags=re.MULTILINE
    )
    # Replace static calls with instance calls
    content = re.sub(rf'{test_class_name}\.processData', 'instance.processData', content)
    content = re.sub(rf'{test_class_name}\.case1', 'instance.case1', content)

with open(output_file, 'w') as f:
    f.write(content)

print(f'DEBUG: Added package declaration and throws Throwable: {package_name}')
" "$TEST_FILE" "$WORK_DIR/src/test/java/${TEST_CLASS_NAME}.java" "$PACKAGE_NAME"

echo "=== Complete Java file copied ==="
head -20 "$WORK_DIR/src/main/java/${MAIN_CLASS_NAME}.java"
echo "..."

# Change to working directory
cd "$WORK_DIR"

# Compile the code
echo "=== Compiling Java code ==="
timeout $TIMEOUT_DURATION mvn compile -q
if [ $? -ne 0 ]; then
    echo "ERROR: Compilation failed"
    exit 1
fi
echo "✓ Compilation successful"

# Compile tests
echo "=== Compiling tests ==="
timeout $TIMEOUT_DURATION mvn test-compile -q
if [ $? -ne 0 ]; then
    echo "ERROR: Test compilation failed"
    exit 1
fi
echo "✓ Test compilation successful"

# Run tests
echo "=== Running tests ==="
TEST_OUTPUT=$(timeout $TIMEOUT_DURATION mvn test 2>&1)
TEST_EXIT_CODE=$?

# Output the test results for debugging
echo "$TEST_OUTPUT"

# Parse test results from Maven output
echo "=== Test Results ==="
TOTAL_TESTS=0
FAILED_TESTS=0
ERROR_TESTS=0
SKIPPED_TESTS=0

# Parse Maven's test summary line: "Tests run: 5, Failures: 4, Errors: 1, Skipped: 0"
if echo "$TEST_OUTPUT" | grep -q "Tests run:"; then
    # Get the most comprehensive test summary line (usually in Results section)
    if echo "$TEST_OUTPUT" | grep -A5 "Results:" | grep -q "Tests run:"; then
        TEST_SUMMARY=$(echo "$TEST_OUTPUT" | grep -A5 "Results:" | grep "Tests run:" | tail -1)
    else
        TEST_SUMMARY=$(echo "$TEST_OUTPUT" | grep "Tests run:" | tail -1)
    fi
    echo "Found test summary: $TEST_SUMMARY"
    
    # Extract numbers using more robust parsing with multiple patterns
    TOTAL_TESTS=$(echo "$TEST_SUMMARY" | sed -n 's/.*Tests run: \([0-9]*\).*/\1/p')
    
    # Handle different output formats
    if echo "$TEST_SUMMARY" | grep -q "Failures:"; then
        FAILED_TESTS=$(echo "$TEST_SUMMARY" | sed -n 's/.*Failures: \([0-9]*\).*/\1/p')
    else
        FAILED_TESTS=0
    fi
    
    if echo "$TEST_SUMMARY" | grep -q "Errors:"; then
        ERROR_TESTS=$(echo "$TEST_SUMMARY" | sed -n 's/.*Errors: \([0-9]*\).*/\1/p')
    else
        ERROR_TESTS=0
    fi
    
    if echo "$TEST_SUMMARY" | grep -q "Skipped:"; then
        SKIPPED_TESTS=$(echo "$TEST_SUMMARY" | sed -n 's/.*Skipped: \([0-9]*\).*/\1/p')
    else
        SKIPPED_TESTS=0
    fi
    
    # Set defaults if extraction failed
    TOTAL_TESTS=${TOTAL_TESTS:-0}
    FAILED_TESTS=${FAILED_TESTS:-0}
    ERROR_TESTS=${ERROR_TESTS:-0}
    SKIPPED_TESTS=${SKIPPED_TESTS:-0}
    
    PASSED_TESTS=$((TOTAL_TESTS - FAILED_TESTS - ERROR_TESTS - SKIPPED_TESTS))
    
    echo "Total tests: $TOTAL_TESTS"
    echo "Passed: $PASSED_TESTS"
    echo "Failed: $FAILED_TESTS"
    echo "Errors: $ERROR_TESTS"
    echo "Skipped: $SKIPPED_TESTS"
    
    if [ "$TOTAL_TESTS" -gt 0 ]; then
        SCORE=$(echo "scale=4; $PASSED_TESTS / $TOTAL_TESTS" | bc -l)
        echo "Score: $SCORE"
    else
        echo "Score: 0"
    fi
else
    echo "No test results found in Maven output"
    echo "Total tests: 0"
    echo "Score: 0"
fi

# Output test logs if there were failures
if [ $TEST_EXIT_CODE -ne 0 ]; then
    echo "=== Test Output ==="
    if [ -f "target/surefire-reports/TEST-*.xml" ]; then
        cat target/surefire-reports/*.txt 2>/dev/null || true
    fi
fi

# Cleanup
cd /
rm -rf "$WORK_DIR"
rm -rf "/tmp/maven-repo-$$"

echo "=== Patch Evaluation Complete ==="
exit $TEST_EXIT_CODE 