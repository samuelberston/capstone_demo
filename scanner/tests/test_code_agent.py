from scanner.agents.code_agent import CodeAnalysisAgent
import logging
import json

# Configure logging with more detail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_xss_finding():
    # Path to your Juice Shop repository
    repo_path = "/Users/samuelberston/Documents/MICS/courses/capstone/juice-shop"
    
    logger.info("Starting XSS finding test")
    
    # Direct CodeQL finding object
    xss_finding = {
      "ruleId": "js/xss",
      "ruleIndex": 37,
      "rule": { "id": "js/xss", "index": 37 },
      "message": {
        "text": "Cross-site scripting vulnerability due to [user-provided value](1)."
      },
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": {
              "uri": "frontend/src/app/search-result/search-result.component.ts",
              "uriBaseId": "%SRCROOT%",
              "index": 31
            },
            "region": {
              "startLine": 151,
              "startColumn": 65,
              "endColumn": 75
            }
          }
        }
      ],
      "partialFingerprints": {
        "primaryLocationLineHash": "61fdae2cc6ff3730:1",
        "primaryLocationStartColumnFingerprint": "58"
      },
      "codeFlows": [
        {
          "threadFlows": [
            {
              "locations": [
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 144,
                        "startColumn": 30,
                        "endColumn": 61
                      }
                    },
                    "message": { "text": "this.ro ... yParams" }
                  }
                },
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 144,
                        "startColumn": 9,
                        "endColumn": 63
                      }
                    },
                    "message": { "text": "queryParam" }
                  }
                },
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 146,
                        "startColumn": 20,
                        "endColumn": 30
                      }
                    },
                    "message": { "text": "queryParam" }
                  }
                },
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 146,
                        "startColumn": 20,
                        "endColumn": 37
                      }
                    },
                    "message": { "text": "queryParam.trim()" }
                  }
                },
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 146,
                        "startColumn": 7,
                        "endColumn": 37
                      }
                    },
                    "message": { "text": "queryParam" }
                  }
                },
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 151,
                        "startColumn": 65,
                        "endColumn": 75
                      }
                    },
                    "message": { "text": "queryParam" }
                  }
                }
              ]
            }
          ]
        },
        {
          "threadFlows": [
            {
              "locations": [
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 144,
                        "startColumn": 30,
                        "endColumn": 61
                      }
                    },
                    "message": { "text": "this.ro ... yParams" }
                  }
                },
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 144,
                        "startColumn": 9,
                        "endColumn": 63
                      }
                    },
                    "message": { "text": "queryParam" }
                  }
                },
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 145,
                        "startColumn": 9,
                        "endColumn": 19
                      }
                    },
                    "message": { "text": "queryParam" }
                  }
                },
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 146,
                        "startColumn": 7,
                        "endColumn": 17
                      }
                    },
                    "message": { "text": "queryParam" }
                  }
                },
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 146,
                        "startColumn": 20,
                        "endColumn": 30
                      }
                    },
                    "message": { "text": "queryParam" }
                  }
                },
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 146,
                        "startColumn": 20,
                        "endColumn": 37
                      }
                    },
                    "message": { "text": "queryParam.trim()" }
                  }
                },
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 146,
                        "startColumn": 7,
                        "endColumn": 37
                      }
                    },
                    "message": { "text": "queryParam" }
                  }
                },
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 150,
                        "startColumn": 32,
                        "endColumn": 42
                      }
                    },
                    "message": { "text": "queryParam" }
                  }
                },
                {
                  "location": {
                    "physicalLocation": {
                      "artifactLocation": {
                        "uri": "frontend/src/app/search-result/search-result.component.ts",
                        "uriBaseId": "%SRCROOT%",
                        "index": 31
                      },
                      "region": {
                        "startLine": 151,
                        "startColumn": 65,
                        "endColumn": 75
                      }
                    },
                    "message": { "text": "queryParam" }
                  }
                }
              ]
            }
          ]
        }
      ],
      "relatedLocations": [
        {
          "id": 1,
          "physicalLocation": {
            "artifactLocation": {
              "uri": "frontend/src/app/search-result/search-result.component.ts",
              "uriBaseId": "%SRCROOT%",
              "index": 31
            },
            "region": {
              "startLine": 144,
              "startColumn": 30,
              "endColumn": 61
            }
          },
          "message": { "text": "user-provided value" }
        }
      ]
    }
    
    # Initialize the agent with repository path
    logger.info("Initializing CodeAnalysisAgent")
    agent = CodeAnalysisAgent(repo_path=repo_path)

    # Run analysis
    logger.info("Running analysis")
    result = agent.analyze(xss_finding)
    
    # Debug the entire result structure
    logger.info("Full result structure:")
    for key, value in result.items():
        logger.info(f"Key: {key}")
        if isinstance(value, dict):
            logger.info(f"  Nested keys: {list(value.keys())}")
            # Add deeper inspection of nested dictionaries
            for nested_key, nested_value in value.items():
                logger.info(f"    {nested_key}: {type(nested_value)}")
                # Log the content of the analysis_json if found
                if nested_key == "analysis_json":
                    logger.info(f"    Found analysis_json content: {nested_value[:200]}...")
        else:
            logger.info(f"  Type: {type(value)}")
            if isinstance(value, str) and len(value) > 100:
                logger.info(f"  First 100 chars: {value[:100]}...")
                # Log if this might be our JSON content
                if "description" in value.lower() and "recommendations" in value.lower():
                    logger.info(f"  Possible JSON content found in {key}: {value[:200]}...")

    # Print results with additional debugging
    print("\nAnalysis Results:")
    print("-" * 50)
    
    logger.info("Checking code context")
    print("\nCode Context:")
    print(result.get("code_context", "No code context available"))
    
    logger.info("Checking raw analysis")
    print("\nRaw Analysis:")
    raw_analysis = result.get("analysis", "No raw analysis available")
    print(raw_analysis)
    
    logger.info("Checking JSON-formatted analysis")
    print("\nJSON-Formatted Analysis:")
    
    # Check all possible locations for JSON analysis with more detailed logging
    possible_locations = [
        ("Direct in result", result.get("analysis_json")),
        ("In context", result.get("context", {}).get("analysis_json")),
        ("In final state", result.get("final_state", {}).get("context", {}).get("analysis_json")),
        ("In raw analysis", raw_analysis)
    ]
    
    for location_name, json_content in possible_locations:
        logger.info(f"Checking {location_name}")
        if json_content:
            logger.info(f"Found content at {location_name}")
            logger.info(f"Content type: {type(json_content)}")
            logger.info(f"Content preview: {str(json_content)[:200]}...")
            
            # Try to extract JSON from markdown-style content
            if isinstance(json_content, str):
                # Look for JSON-like structures
                if "{" in json_content and "}" in json_content:
                    try:
                        # Try to find and parse JSON object within the content
                        start_idx = json_content.find("{")
                        end_idx = json_content.rfind("}") + 1
                        if start_idx >= 0 and end_idx > start_idx:
                            potential_json = json_content[start_idx:end_idx]
                            parsed = json.loads(potential_json)
                            logger.info(f"Successfully extracted and parsed JSON from {location_name}")
                            logger.info(f"JSON structure: {list(parsed.keys())}")
                            json_analysis = potential_json
                            break
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse potential JSON from {location_name}: {e}")
                        logger.error(f"Failed content: {potential_json[:500]}...")
        else:
            logger.info(f"No content at {location_name}")
    else:
        json_analysis = "No JSON analysis available"
    
    print(json_analysis)

    # Log the complete result structure with more detail
    logger.info("Complete result structure:")
    logger.info("Result keys: %s", list(result.keys()))
    logger.info("Context keys (if present): %s", 
                list(result.get("context", {}).keys()) if "context" in result else "No context found")
    logger.info("Raw analysis preview: %s", 
                result.get("analysis", "")[:200] if result.get("analysis") else "No analysis found")

if __name__ == "__main__":
    test_xss_finding()