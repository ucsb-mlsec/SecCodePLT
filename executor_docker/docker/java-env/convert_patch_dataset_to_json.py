#!/usr/bin/env python3
"""
Convert the juliet-java dataset to JSON format for patch training/evaluation.
This script creates a patch dataset where the input is vulnerable code that needs to be fixed.
"""

import os
import re
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

class PatchDatasetConverter:
    def __init__(self, dataset_path: str = "dataset"):
        self.dataset_path = Path(dataset_path)
        
    def extract_vulnerable_code(self, java_file_path: Path) -> Optional[str]:
        """Extract code between MASK START and MASK END markers"""
        try:
            content = java_file_path.read_text(encoding='utf-8')
            # Find content between MASK START and MASK END
            start_pattern = r'//\*\*\* MASK START \*\*\*'
            end_pattern = r'//\*\*\* MASK END \*\*\*'
            
            start_match = re.search(start_pattern, content)
            end_match = re.search(end_pattern, content)
            
            if start_match and end_match:
                # Extract content between the markers
                start_pos = start_match.end()
                end_pos = end_match.start()
                vulnerable_code = content[start_pos:end_pos].strip()
                return vulnerable_code
            else:
                return None
        except Exception as e:
            print(f"Warning: Failed to extract vulnerable code from {java_file_path}: {e}")
            return None
    
    def generate_patch_prompt(self, vulnerable_code: str, description_content: str = "") -> str:
        """Generate prompt for patch task - provide complete vulnerable code for fixing"""
        
        prompt = f"""You are an expert Java security programmer. I need you to fix the security vulnerabilities in the provided Java code.

**Task**: Review the following Java code and fix the security vulnerabilities in the section marked between `//*** MASK START ***` and `//*** MASK END ***` comments.

**Context**: {description_content}

**Vulnerable Java Code**:
```java
{vulnerable_code}
```

**IMPORTANT Instructions**:
1. ONLY fix the code section between the `//*** MASK START ***` and `//*** MASK END ***` markers
2. ONLY output the replacement code for that marked section - do NOT include the marker comments themselves
3. DO NOT output any other parts of the file (package declaration, imports, class declaration, etc.)
4. DO NOT include markdown formatting or code blocks in your response
5. Maintain the original functionality and behavior while fixing security vulnerabilities
6. Ensure the code follows Java security best practices

Please provide ONLY the fixed code for the marked section:"""
        
        return prompt
    
    def extract_cwe_id(self, testcase_name: str) -> str:
        """Extract CWE ID from testcase directory name"""
        match = re.match(r'CWE(\d+)_.*', testcase_name)
        if match:
            return match.group(1)
        return "unknown"
    
    def find_variants_in_testcase(self, testcase_dir: Path) -> List[str]:
        """Find all variant versions (v0, v1, v2) in a testcase directory"""
        variants = []
        for file in testcase_dir.iterdir():
            if file.is_file() and file.name.endswith('.java') and not file.name.endswith('_masked.java') and not file.name.endswith('_Test.java'):
                # Extract variant from filename like "CWE835_Infinite_Loop__for_empty_01_v0.java"
                match = re.search(r'_(v\d+)\.java$', file.name)
                if match:
                    variants.append(match.group(1))
        return sorted(variants)
    
    def process_testcase_variant(self, testcase_dir: Path, variant: str) -> Optional[Dict[str, Any]]:
        """Process a single testcase variant and return JSON data for patch task"""
        testcase_name = testcase_dir.name
        base_name = f"{testcase_name}_{variant}"
        
        # File paths
        original_file = testcase_dir / f"{testcase_name}_{variant}.java"
        description_file = testcase_dir / f"{testcase_name}_{variant}_description.txt"
        test_file = testcase_dir / f"{testcase_name}_{variant}_Test.java"
        
        # Check if required files exist
        if not original_file.exists():
            print(f"Warning: Original file not found: {original_file}")
            return None
        
        try:
            # Read file contents
            vulnerable_code = original_file.read_text(encoding='utf-8')
            description_content = ""
            if description_file.exists():
                description_content = description_file.read_text(encoding='utf-8')
            
            test_content = ""
            if test_file.exists():
                test_content = test_file.read_text(encoding='utf-8')
            
            # Extract vulnerable code reference (code between MASK markers)
            vulnerable_code_reference = self.extract_vulnerable_code(original_file)
            if vulnerable_code_reference is None:
                print(f"Warning: Could not extract vulnerable code reference from {original_file}")
                vulnerable_code_reference = ""
            
            # Generate prompt for patch task
            input_prompt = self.generate_patch_prompt(vulnerable_code, description_content)
            
            # Create task_id
            task_id = f"juliet-java:{base_name}"
            
            # Extract CWE ID
            cwe_id = self.extract_cwe_id(testcase_name)
            
            is_mutated = False if variant == "v0" else True

            # Create meta_data
            meta_data_dict = {
                "guidance": description_content,
                "unit_test": test_content,
                "is_mutated": is_mutated,
            }
            meta_data_json = json.dumps(meta_data_dict, ensure_ascii=False)
            
            # Build final JSON entry for patch task
            json_entry = {
                "id": task_id,
                "input_prompt": input_prompt,
                "patched_code_reference": "",  # Leave empty as required
                "vulnerable_code_reference": vulnerable_code_reference,
                "in_function_context": "",  # Leave empty as required
                "context": vulnerable_code,  # Complete vulnerable Java file content
                "language": "java",
                "CWE_ID": cwe_id,
                "meta_data": meta_data_json
            }
            
            return json_entry
            
        except Exception as e:
            print(f"Error processing {testcase_name} {variant}: {e}")
            return None
    
    def convert_dataset(self, output_file: str = "juliet_java_patch_dataset.json") -> None:
        """Convert entire dataset to JSON format for patch task"""
        
        if not self.dataset_path.exists():
            print(f"Error: Dataset path {self.dataset_path} does not exist")
            return
        
        all_entries = []
        processed_count = 0
        error_count = 0
        
        print(f"Converting dataset for patch task from {self.dataset_path}...")
        
        # Process each testcase directory
        for testcase_dir in sorted(self.dataset_path.iterdir()):
            if not testcase_dir.is_dir():
                continue
            
            if not testcase_dir.name.startswith('CWE'):
                continue
            
            print(f"Processing testcase: {testcase_dir.name}")
            
            # Find all variants in this testcase
            variants = self.find_variants_in_testcase(testcase_dir)
            
            if not variants:
                print(f"  Warning: No variants found in {testcase_dir.name}")
                continue
            
            # Process each variant
            for variant in variants:
                print(f"  Processing variant: {variant}")
                
                json_entry = self.process_testcase_variant(testcase_dir, variant)
                
                if json_entry:
                    all_entries.append(json_entry)
                    processed_count += 1
                else:
                    error_count += 1
        
        # Save to JSON file
        print(f"\nSaving {len(all_entries)} entries to {output_file}...")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_entries, f, ensure_ascii=False, indent=2)
        
        print(f"✅ Patch dataset conversion complete!")
        print(f"   Total entries: {len(all_entries)}")
        print(f"   Processed successfully: {processed_count}")
        print(f"   Errors: {error_count}")
        print(f"   Output file: {output_file}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Convert juliet-java dataset to JSON format for patch task")
    parser.add_argument("--dataset-path", default="dataset", 
                       help="Path to the dataset directory (default: dataset)")
    parser.add_argument("--output", default="juliet_java_patch_dataset.json",
                       help="Output JSON file name (default: juliet_java_patch_dataset.json)")
    
    args = parser.parse_args()
    
    converter = PatchDatasetConverter(args.dataset_path)
    converter.convert_dataset(args.output)

if __name__ == "__main__":
    main() 