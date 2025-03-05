from scanner.agents.code_agent import CodeAnalysisAgent

def test_xss_finding():
    # Path to your Juice Shop repository
    repo_path = "/Users/samuelberston/Documents/MICS/courses/capstone/juice-shop"
    
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
    agent = CodeAnalysisAgent(repo_path=repo_path)

    # Run analysis
    result = agent.analyze(xss_finding)

    # Print results
    print("Analysis Results:")
    print("-" * 50)
    print("\nCode Context:")
    print(result["code_context"])
    print("\nAnalysis:")
    print(result["analysis"])

if __name__ == "__main__":
    test_xss_finding()