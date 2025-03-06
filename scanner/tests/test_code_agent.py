from scanner.agents.code_agent import CodeAnalysisAgent

def test_xss_finding():
    # Path to your Juice Shop repository
    repo_path = "/Users/samuelberston/Documents/MICS/courses/capstone/juice-shop"
    
    # Direct CodeQL finding object
    xss_finding = {
          "ruleId": "js/request-forgery",
          "ruleIndex": 17,
          "rule": { "id": "js/request-forgery", "index": 17 },
          "message": {
            "text": "The [URL](1) of this request depends on a [user-provided value](2)."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "routes/profileImageUrlUpload.ts",
                  "uriBaseId": "%SRCROOT%",
                  "index": 1
                },
                "region": {
                  "startLine": 22,
                  "startColumn": 30,
                  "endLine": 23,
                  "endColumn": 20
                }
              }
            }
          ],
          "partialFingerprints": {
            "primaryLocationLineHash": "681cd2267e1fcfff:1",
            "primaryLocationStartColumnFingerprint": "21"
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
                            "uri": "routes/profileImageUrlUpload.ts",
                            "uriBaseId": "%SRCROOT%",
                            "index": 1
                          },
                          "region": {
                            "startLine": 18,
                            "startColumn": 19,
                            "endColumn": 27
                          }
                        },
                        "message": { "text": "req.body" }
                      }
                    },
                    {
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": {
                            "uri": "routes/profileImageUrlUpload.ts",
                            "uriBaseId": "%SRCROOT%",
                            "index": 1
                          },
                          "region": {
                            "startLine": 18,
                            "startColumn": 13,
                            "endColumn": 36
                          }
                        },
                        "message": { "text": "url" }
                      }
                    },
                    {
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": {
                            "uri": "routes/profileImageUrlUpload.ts",
                            "uriBaseId": "%SRCROOT%",
                            "index": 1
                          },
                          "region": {
                            "startLine": 23,
                            "startColumn": 16,
                            "endColumn": 19
                          }
                        },
                        "message": { "text": "url" }
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
                            "uri": "routes/profileImageUrlUpload.ts",
                            "uriBaseId": "%SRCROOT%",
                            "index": 1
                          },
                          "region": {
                            "startLine": 18,
                            "startColumn": 19,
                            "endColumn": 27
                          }
                        },
                        "message": { "text": "req.body" }
                      }
                    },
                    {
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": {
                            "uri": "routes/profileImageUrlUpload.ts",
                            "uriBaseId": "%SRCROOT%",
                            "index": 1
                          },
                          "region": {
                            "startLine": 18,
                            "startColumn": 13,
                            "endColumn": 36
                          }
                        },
                        "message": { "text": "url" }
                      }
                    },
                    {
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": {
                            "uri": "routes/profileImageUrlUpload.ts",
                            "uriBaseId": "%SRCROOT%",
                            "index": 1
                          },
                          "region": {
                            "startLine": 19,
                            "startColumn": 11,
                            "endColumn": 14
                          }
                        },
                        "message": { "text": "url" }
                      }
                    },
                    {
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": {
                            "uri": "routes/profileImageUrlUpload.ts",
                            "uriBaseId": "%SRCROOT%",
                            "index": 1
                          },
                          "region": {
                            "startLine": 23,
                            "startColumn": 16,
                            "endColumn": 19
                          }
                        },
                        "message": { "text": "url" }
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
                  "uri": "routes/profileImageUrlUpload.ts",
                  "uriBaseId": "%SRCROOT%",
                  "index": 1
                },
                "region": {
                  "startLine": 23,
                  "startColumn": 16,
                  "endColumn": 19
                }
              },
              "message": { "text": "URL" }
            },
            {
              "id": 2,
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "routes/profileImageUrlUpload.ts",
                  "uriBaseId": "%SRCROOT%",
                  "index": 1
                },
                "region": {
                  "startLine": 18,
                  "startColumn": 19,
                  "endColumn": 27
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