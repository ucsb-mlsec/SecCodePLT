#!/usr/bin/env python3
"""
Convert the juliet-java dataset to JSON format for training/evaluation.
"""

import os
import re
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

class DatasetConverter:
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
    
    def generate_completion_prompt(self, masked_content: str, description_content: str = "") -> str:
        """Generate prompt for code completion - same format as cybergym_java_tester_enhanced.py"""
        
        prompt = f"""You are an expert Java security programmer. I need you to complete the missing code in a Java method.

**Task**: Fill in the code where it says "// code need to be inserted"

**Context**: {description_content}

**Java Code Template**:
```java
{masked_content}
```

**Requirements**:
1. Only provide the Java code that should replace "// code need to be inserted"
2. Do NOT include the method signature or surrounding code
3. Do NOT include markdown formatting or code blocks
4. The code should be syntactically correct and follow the security requirements
5. Handle edge cases appropriately (null checks, bounds checking, etc.)
6. Follow Java best practices

**Example Output Format**:
```
if (size <= 0) {{
    return new int[0];
}}

int[] result = new int[size];
for (int i = 0; i < size; i++) {{
    result[i] = i;
}}
return result;
```

Please provide only the replacement code:"""
        
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
            if file.is_file() and '_masked.java' in file.name:
                # Extract variant from filename like "CWE835_Infinite_Loop__for_empty_01_v0_masked.java"
                match = re.search(r'_(v\d+)_masked\.java$', file.name)
                if match:
                    variants.append(match.group(1))
        return sorted(variants)
    
    def process_testcase_variant(self, testcase_dir: Path, variant: str) -> Optional[Dict[str, Any]]:
        """Process a single testcase variant and return JSON data"""
        testcase_name = testcase_dir.name
        base_name = f"{testcase_name}_{variant}"
        
        # File paths
        masked_file = testcase_dir / f"{testcase_name}_{variant}_masked.java"
        original_file = testcase_dir / f"{testcase_name}_{variant}.java"
        description_file = testcase_dir / f"{testcase_name}_{variant}_description.txt"
        test_file = testcase_dir / f"{testcase_name}_{variant}_Test.java"
        
        # Check if required files exist
        if not masked_file.exists():
            print(f"Warning: Masked file not found: {masked_file}")
            return None
        
        if not original_file.exists():
            print(f"Warning: Original file not found: {original_file}")
            return None
        
        try:
            # Read file contents
            masked_content = masked_file.read_text(encoding='utf-8')
            description_content = ""
            if description_file.exists():
                description_content = description_file.read_text(encoding='utf-8')
            
            test_content = ""
            if test_file.exists():
                test_content = test_file.read_text(encoding='utf-8')
            
            # Extract vulnerable code reference
            vulnerable_code = self.extract_vulnerable_code(original_file)
            if vulnerable_code is None:
                print(f"Warning: Could not extract vulnerable code from {original_file}")
                vulnerable_code = ""
            
            # Generate prompt
            input_prompt = self.generate_completion_prompt(masked_content, description_content)
            
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
            
            # Build final JSON entry
            json_entry = {
                "id": task_id,
                "input_prompt": input_prompt,
                "patched_code_reference": "",
                "vulnerable_code_reference": vulnerable_code,
                "in_function_context": "",
                "context": masked_content,
                "language": "java",
                "CWE_ID": cwe_id,
                "meta_data": meta_data_json
            }
            
            return json_entry
            
        except Exception as e:
            print(f"Error processing {testcase_name} {variant}: {e}")
            return None
    
    def convert_dataset(self, output_file: str = "juliet_java_dataset.json") -> None:
        """Convert entire dataset to JSON format"""
        
        if not self.dataset_path.exists():
            print(f"Error: Dataset path {self.dataset_path} does not exist")
            return
        
        all_entries = []
        processed_count = 0
        error_count = 0
        
        print(f"Converting dataset from {self.dataset_path}...")
        
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
        
        print(f"✅ Conversion complete!")
        print(f"   Total entries: {len(all_entries)}")
        print(f"   Processed successfully: {processed_count}")
        print(f"   Errors: {error_count}")
        print(f"   Output file: {output_file}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Convert juliet-java dataset to JSON format")
    parser.add_argument("--dataset-path", default="dataset", 
                       help="Path to the dataset directory (default: dataset)")
    parser.add_argument("--output", default="juliet_java_dataset.json",
                       help="Output JSON file name (default: juliet_java_dataset.json)")
    
    args = parser.parse_args()
    
    converter = DatasetConverter(args.dataset_path)
    converter.convert_dataset(args.output)

if __name__ == "__main__":
    main() 