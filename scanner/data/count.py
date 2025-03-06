import json
from collections import Counter

def count_results(json_file):
    # Load and parse the JSON data
    data = json.loads(json_file)
    
    # Get the results array
    results = data.get("results", [])
    
    # Extract ruleIds from results
    rule_ids = [result.get("ruleId") for result in results if result.get("ruleId")]
    
    # Count frequency of each rule
    rule_counts = Counter(rule_ids)
    
    return rule_counts

# Example usage
with open('juice-shop-codeql.json', 'r') as file:
    json_content = file.read()
    rule_frequencies = count_results(json_content)
    
    # Print total number of results
    print(f"Total number of results: {sum(rule_frequencies.values())}")
    
    # Print each rule and its frequency
    print("\nRule frequencies:")
    for rule, count in rule_frequencies.most_common():
        print(f"{rule}: {count}")