import json
import logging
import os
from pathlib import Path
from scanner.agents.dependency_agent import DependencyAnalysisAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Test data - express-jwt dependency finding
TEST_FINDING = {
  "isVirtual": "true",
  "fileName": "express-jwt:0.1.3",
  "filePath": "/data/juice-shop/build/package-lock.json?/express-jwt:0.1.3",
  "description": "JWT authentication middleware.",
  "projectReferences": ["juice-shop:17.1.1"],
  "relatedDependencies": [
    {
      "isVirtual": "true",
      "fileName": "express-jwt:0.1.3",
      "filePath": "/data/juice-shop/package-lock.json?/express-jwt:0.1.3",
      "packageIds": [{ "id": "pkg:npm/express-jwt@0.1.3" }]
    }
  ],
  "evidenceCollected": {
    "vendorEvidence": [
      {
        "type": "vendor",
        "confidence": "HIGHEST",
        "source": "package.json",
        "name": "author.email",
        "value": "matias@auth0.com"
      },
      {
        "type": "vendor",
        "confidence": "HIGHEST",
        "source": "package.json",
        "name": "author.name",
        "value": "Matias Woloski"
      },
      {
        "type": "vendor",
        "confidence": "HIGHEST",
        "source": "package.json",
        "name": "author.url",
        "value": "https://www.auth0.com/"
      },
      {
        "type": "vendor",
        "confidence": "HIGHEST",
        "source": "package.json",
        "name": "bugs.url",
        "value": "http://github.com/auth0/express-jwt/issues"
      },
      {
        "type": "vendor",
        "confidence": "HIGHEST",
        "source": "package.json",
        "name": "description",
        "value": "JWT authentication middleware."
      },
      {
        "type": "vendor",
        "confidence": "HIGHEST",
        "source": "package.json",
        "name": "name",
        "value": "express-jwt"
      },
      {
        "type": "vendor",
        "confidence": "HIGHEST",
        "source": "package.json",
        "name": "name",
        "value": "express-jwt_project"
      }
    ],
    "productEvidence": [
      {
        "type": "product",
        "confidence": "HIGHEST",
        "source": "package.json",
        "name": "name",
        "value": "express-jwt"
      }
    ],
    "versionEvidence": [
      {
        "type": "version",
        "confidence": "HIGHEST",
        "source": "package.json",
        "name": "version",
        "value": "0.1.3"
      }
    ]
  },
  "packages": [
    {
      "id": "pkg:npm/express-jwt@0.1.3",
      "confidence": "HIGHEST",
      "url": "https://ossindex.sonatype.org/component/pkg:npm/express-jwt@0.1.3?utm_source=dependency-check&utm_medium=integration&utm_content=12.1.0"
    }
  ],
  "vulnerabilityIds": [
    {
      "id": "cpe:2.3:a:auth0:express-jwt:0.1.3:*:*:*:*:*:*:*",
      "confidence": "HIGHEST",
      "url": "https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&cpe_vendor=cpe%3A%2F%3Aauth0&cpe_product=cpe%3A%2F%3Aauth0%3Aexpress-jwt&cpe_version=cpe%3A%2F%3Aauth0%3Aexpress-jwt%3A0.1.3"
    }
  ],
  "vulnerabilities": [
    {
      "source": "NVD",
      "name": "CVE-2020-15084",
      "severity": "CRITICAL",
      "cvssv2": {
        "score": 4.3,
        "accessVector": "NETWORK",
        "accessComplexity": "MEDIUM",
        "authenticationr": "NONE",
        "confidentialityImpact": "NONE",
        "integrityImpact": "PARTIAL",
        "availabilityImpact": "NONE",
        "severity": "MEDIUM",
        "version": "2.0",
        "exploitabilityScore": "8.6",
        "impactScore": "2.9"
      },
      "cvssv3": {
        "baseScore": 9.1,
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
        "privilegesRequired": "NONE",
        "userInteraction": "NONE",
        "scope": "UNCHANGED",
        "confidentialityImpact": "HIGH",
        "integrityImpact": "HIGH",
        "availabilityImpact": "NONE",
        "baseSeverity": "CRITICAL",
        "exploitabilityScore": "3.9",
        "impactScore": "5.2",
        "version": "3.1"
      },
      "cwes": ["CWE-863", "CWE-285"],
      "description": "In express-jwt (NPM package) up and including version 5.3.3, the algorithms entry to be specified in the configuration is not being enforced. When algorithms is not specified in the configuration, with the combination of jwks-rsa, it may lead to authorization bypass. You are affected by this vulnerability if all of the following conditions apply: - You are using express-jwt - You do not have **algorithms** configured in your express-jwt configuration. - You are using libraries such as jwks-rsa as the **secret**. You can fix this by specifying **algorithms** in the express-jwt configuration. See linked GHSA for example. This is also fixed in version 6.0.0.",
      "notes": "",
      "references": [
        {
          "source": "OSSIndex",
          "url": "https://github.com/auth0/express-jwt/security/advisories/GHSA-6g6m-m6h5-w9gf",
          "name": "https://github.com/auth0/express-jwt/security/advisories/GHSA-6g6m-m6h5-w9gf"
        },
        {
          "source": "af854a3a-2127-422b-91ae-364da2661108",
          "url": "https://github.com/auth0/express-jwt/security/advisories/GHSA-6g6m-m6h5-w9gf",
          "name": "THIRD_PARTY_ADVISORY"
        },
        {
          "source": "security-advisories@github.com",
          "url": "https://github.com/auth0/express-jwt/security/advisories/GHSA-6g6m-m6h5-w9gf",
          "name": "THIRD_PARTY_ADVISORY"
        },
        {
          "source": "security-advisories@github.com",
          "url": "https://github.com/auth0/express-jwt/commit/7ecab5f8f0cab5297c2b863596566eb0c019cdef",
          "name": "PATCH,THIRD_PARTY_ADVISORY"
        },
        {
          "source": "OSSINDEX",
          "url": "https://ossindex.sonatype.org/vulnerability/CVE-2020-15084?component-type=npm&component-name=express-jwt&utm_source=dependency-check&utm_medium=integration&utm_content=12.1.0",
          "name": "[CVE-2020-15084] CWE-285: Improper Authorization"
        },
        {
          "source": "OSSIndex",
          "url": "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2020-15084",
          "name": "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2020-15084"
        },
        {
          "source": "af854a3a-2127-422b-91ae-364da2661108",
          "url": "https://github.com/auth0/express-jwt/commit/7ecab5f8f0cab5297c2b863596566eb0c019cdef",
          "name": "PATCH,THIRD_PARTY_ADVISORY"
        }
      ],
      "vulnerableSoftware": [
        {
          "software": {
            "id": "cpe:2.3:a:auth0:express-jwt:*:*:*:*:*:node.js:*:*",
            "vulnerabilityIdMatched": "true",
            "versionEndIncluding": "5.3.3"
          }
        }
      ]
    },
    {
      "source": "NPM",
      "name": "GHSA-6g6m-m6h5-w9gf",
      "unscored": "true",
      "severity": "high",
      "cvssv3": {
        "baseScore": 7.699999809265137,
        "attackVector": "NETWORK",
        "attackComplexity": "HIGH",
        "privilegesRequired": "LOW",
        "userInteraction": "REQUIRED",
        "scope": "CHANGED",
        "confidentialityImpact": "HIGH",
        "integrityImpact": "HIGH",
        "availabilityImpact": "NONE",
        "baseSeverity": "HIGH",
        "version": "3.1"
      },
      "cwes": ["CWE-863", "CWE-285"],
      "description": "### Overview\nVersions before and including 5.3.3, we are not enforcing the **algorithms** entry to be specified in the configuration.\nWhen **algorithms** is not specified in the configuration, with the combination of jwks-rsa, it may lead to authorization bypass. \n\n### Am I affected?\nYou are affected by this vulnerability if all of the following conditions apply:\n\nYou are using express-jwt\nAND \nYou do not have **algorithms**  configured in your express-jwt configuration.\nAND\nYou are using libraries such as jwks-rsa as the **secret**. \n\n### How to fix that?\nSpecify **algorithms** in the express-jwt configuration. The following is an example of a proper configuration\n\n``` \nconst checkJwt = jwt({\n  secret: jwksRsa.expressJwtSecret({\n    rateLimit: true,\n    jwksRequestsPerMinute: 5,\n    jwksUri: `https://${DOMAIN}/.well-known/jwks.json`\n  }),\n  // Validate the audience and the issuer.\n  audience: process.env.AUDIENCE,\n  issuer: `https://${DOMAIN}/`,\n  // restrict allowed algorithms\n  algorithms: ['RS256']\n}); \n```\n\n### Will this update impact my users?\nThe fix provided in patch will not affect your users if you specified the algorithms allowed. The patch now makes **algorithms** a required configuration. \n\n\n### Credit\nIST Group",
      "notes": "",
      "references": [
        {
          "source": "NPM Advisory reference: ",
          "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-15084",
          "name": "https://nvd.nist.gov/vuln/detail/CVE-2020-15084"
        },
        {
          "source": "NPM Advisory reference: ",
          "url": "https://github.com/auth0/express-jwt/commit/7ecab5f8f0cab5297c2b863596566eb0c019cdef",
          "name": "https://github.com/auth0/express-jwt/commit/7ecab5f8f0cab5297c2b863596566eb0c019cdef"
        },
        {
          "source": "NPM Advisory reference: ",
          "url": "https://github.com/auth0/express-jwt/security/advisories/GHSA-6g6m-m6h5-w9gf",
          "name": "https://github.com/auth0/express-jwt/security/advisories/GHSA-6g6m-m6h5-w9gf"
        },
        {
          "source": "NPM Advisory reference: ",
          "url": "https://github.com/advisories/GHSA-6g6m-m6h5-w9gf",
          "name": "https://github.com/advisories/GHSA-6g6m-m6h5-w9gf"
        }
      ],
      "vulnerableSoftware": [
        {
          "software": {
            "id": "cpe:2.3:a:*:express-jwt:\\<\\=5.3.3:*:*:*:*:*:*:*"
          }
        }
      ]
    }
  ]
}

def test_dependency_agent():
    """Test the dependency agent with express-jwt finding."""
    try:
        # Initialize the agent with the juice-shop repo path
        repo_path = '/Users/samuelberston/Documents/MICS/courses/capstone/juice-shop'
        
        # Verify the repo path exists
        if not os.path.exists(repo_path):
            raise FileNotFoundError(f"Could not find repository at {repo_path}")
            
        logger.info(f"Initializing agent with repo path: {repo_path}")
        agent = DependencyAnalysisAgent(repo_path=repo_path)
        
        # Create dependency info using the test finding
        dependency = {
            'name': 'express-jwt',
            'version': '0.1.3',
            'context': TEST_FINDING
        }
        
        # Run the analysis
        logger.info("Starting dependency analysis")
        result = agent.analyze(dependency)
        
        # Extract analysis content from messages
        analysis_content = None
        if result.get('messages'):
            for message in result['messages']:
                if hasattr(message, 'content'):
                    analysis_content = message.content
                    break
        
        # Log the results in a more concise way
        logger.info("Analysis Results:")
        logger.info("Dependency Info:")
        logger.info(f"  Name: {dependency['name']}")
        logger.info(f"  Version: {dependency['version']}")
        
        logger.info("\nVulnerability Info:")
        logger.info(f"  CVEs: {result.get('vulnerability_info', {}).get('cves', [])}")
        logger.info(f"  Severity: {result.get('vulnerability_info', {}).get('severities', [])}")
        logger.info(f"  CWEs: {result.get('vulnerability_info', {}).get('cwes', [])}")
        
        logger.info("\nUsage Analysis:")
        usage = result.get('usage_info', {})
        logger.info(f"  Files analyzed: {usage.get('files_analyzed', 0)}")
        logger.info(f"  Import statements found: {len(usage.get('import_statements', []))}")
        logger.info(f"  Configuration patterns found: {len(usage.get('configuration', []))}")
        logger.info(f"  Direct usage patterns found: {len(usage.get('direct_usage', []))}")
        
        logger.info("\nJSON Formatted Analysis:")
        if result.get('analysis', {}).get('json_format'):
            try:
                json_analysis = json.loads(result['analysis']['json_format'])
                logger.info(json.dumps(json_analysis, indent=2))
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing JSON analysis: {e}")
                logger.info(result['analysis']['json_format'])
        else:
            logger.info("  No JSON formatted analysis available")
        
        logger.info("\nDetailed Analysis:")
        if result.get('analysis', {}).get('content'):
            logger.info(f"  Analysis: {result['analysis']['content']}")
        else:
            logger.info("  No detailed analysis content available")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in dependency agent test: {str(e)}", exc_info=True)
        raise

if __name__ == "__main__":
    test_dependency_agent()
