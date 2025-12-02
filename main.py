from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn
from typing import List, Dict
import os
from datetime import datetime
import json
import re

# Import CrewAI components
from crewai import Agent, Task, Crew, Process
from crewai.llms import LLM
from langchain_google_genai import ChatGoogleGenerativeAI

app = FastAPI(
    title="Smart Contract Security Auditor",
    description="AI-powered smart contract vulnerability detection using CrewAI + Gemini",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class ContractSubmission(BaseModel):
    contract_name: str
    contract_language: str
    contract_code: str

class AuditResult(BaseModel):
    contract_name: str
    timestamp: str
    severity_score: int
    vulnerabilities: List[Dict]
    gas_optimizations: List[Dict]
    security_recommendations: List[str]
    code_quality_score: int
    detailed_report: str

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    gemini_configured: bool
    
# from litellm import completion, ChatCompletion
# from crewai import Agent

# Initialize Gemini LLM
def get_llm():
    api_key = "GEMINI_API_KEY"
    if not api_key:
        raise ValueError("GEMINI_API_KEY not found in environment variables. Please set it in .env file")
    
    return LLM(
        model="gemini/gemini-2.0-flash",   # Gemini model
        api_key=api_key,
        temperature=0.3
    )

# Create CrewAI Agents
def create_audit_crew(contract_code: str, contract_language: str):
    """Create a crew of AI agents to audit smart contracts"""
    
    llm = get_llm()
    
    # Agent 1: Vulnerability Scanner
    vulnerability_scanner = Agent(
        role="Smart Contract Vulnerability Expert",
        goal="Identify security vulnerabilities including reentrancy, integer overflow, access control issues, and front-running risks",
        backstory="""You are a legendary smart contract security researcher who has 
        discovered numerous critical vulnerabilities in production contracts. You have 
        deep knowledge of common attack vectors and emerging threats.""",
        llm=llm,
        verbose=True,
        allow_delegation=False
    )
    
    # Agent 2: Gas Optimization Specialist
    gas_optimizer = Agent(
        role="Gas Optimization Engineer",
        goal="Analyze code for gas inefficiencies and suggest optimizations to reduce transaction costs",
        backstory="""You are a performance optimization expert specializing in 
        blockchain gas efficiency. You know every trick to minimize gas costs while 
        maintaining security.""",
        llm=llm,
        verbose=True,
        allow_delegation=False
    )
    
    # Agent 3: Code Quality Auditor
    code_quality_auditor = Agent(
        role="Smart Contract Code Quality Reviewer",
        goal="Assess code quality, best practices, maintainability, and documentation",
        backstory="""You are a senior blockchain architect with expertise in 
        clean code principles applied to smart contracts. You ensure code is 
        readable, maintainable, and well-documented.""",
        llm=llm,
        verbose=True,
        allow_delegation=False
    )
    
    # Agent 4: Security Report Writer
    security_reporter = Agent(
        role="Security Report Specialist",
        goal="Compile comprehensive security audit reports with actionable recommendations",
        backstory="""You are a technical writer specializing in security documentation. 
        You transform complex security findings into clear, actionable reports.""",
        llm=llm,
        verbose=True,
        allow_delegation=False
    )
    
    # Define Tasks
    vulnerability_task = Task(
        description=f"""Analyze this {contract_language} smart contract for security vulnerabilities.

Contract Code:
```
{contract_code[:2000]}
```

Identify vulnerabilities like:
1. Reentrancy vulnerabilities
2. Integer overflow/underflow risks
3. Access control issues
4. Unchecked external calls
5. Front-running possibilities

For each vulnerability, provide:
- Type and severity (Critical/High/Medium/Low)
- Description
- How to fix it

Respond in this format:
VULNERABILITY 1: [Type] - [Severity]
Description: [details]
Fix: [recommendation]

VULNERABILITY 2: [Type] - [Severity]
...and so on""",
        agent=vulnerability_scanner,
        expected_output="List of vulnerabilities with severity and fixes"
    )
    
    gas_optimization_task = Task(
        description=f"""Analyze this {contract_language} smart contract for gas optimization opportunities.

Contract Code:
```
{contract_code[:2000]}
```

Find optimization opportunities like:
1. Inefficient storage patterns
2. Redundant operations
3. Expensive loops

For each optimization, provide:
- Location in code
- Current issue
- Optimization technique
- Estimated savings

Respond in this format:
OPTIMIZATION 1: [Issue]
Location: [where]
Technique: [how to fix]
Savings: [estimate]

OPTIMIZATION 2: ...and so on""",
        agent=gas_optimizer,
        expected_output="List of gas optimizations with savings estimates"
    )
    
    code_quality_task = Task(
        description=f"""Review this {contract_language} smart contract for code quality.

Contract Code:
```
{contract_code[:2000]}
```

Evaluate:
1. Code organization and structure
2. Naming conventions
3. Documentation
4. Best practices

Provide:
- Quality score (0-100)
- Issues found
- Recommendations

Respond in this format:
QUALITY SCORE: [0-100]

ISSUES:
1. [Issue description]
2. [Issue description]

RECOMMENDATIONS:
1. [Recommendation]
2. [Recommendation]""",
        agent=code_quality_auditor,
        expected_output="Code quality score and recommendations"
    )
    
    report_task = Task(
        description="""Create a comprehensive security audit summary.

Based on all previous findings, provide:
1. Executive summary
2. Overall risk level (Critical/High/Medium/Low)
3. Top 3 priority recommendations
4. Compliance notes

Respond in this format:
EXECUTIVE SUMMARY:
[2-3 sentence overview]

RISK LEVEL: [Critical/High/Medium/Low]

PRIORITY RECOMMENDATIONS:
1. [Most critical action]
2. [Second priority]
3. [Third priority]

COMPLIANCE: [Any standards compliance notes]""",
        agent=security_reporter,
        expected_output="Executive summary and priority recommendations"
    )
    
    # Create and return crew
    crew = Crew(
        agents=[vulnerability_scanner, gas_optimizer, code_quality_auditor, security_reporter],
        tasks=[vulnerability_task, gas_optimization_task, code_quality_task, report_task],
        process=Process.sequential,
        verbose=True
    )
    
    return crew

def parse_crew_output(result_text: str):
    """Parse the crew output into structured data"""
    vulnerabilities = []
    gas_optimizations = []
    security_recommendations = []
    code_quality_score = 70
    severity_score = 5
    
    # Parse vulnerabilities
    vuln_pattern = r'VULNERABILITY \d+: (.+?) - (Critical|High|Medium|Low)\s*Description: (.+?)\s*Fix: (.+?)(?=VULNERABILITY|OPTIMIZATION|QUALITY|EXECUTIVE|$)'
    vuln_matches = re.findall(vuln_pattern, result_text, re.DOTALL | re.IGNORECASE)
    
    for match in vuln_matches:
        vulnerabilities.append({
            "type": match[0].strip(),
            "severity": match[1].strip(),
            "lines": "Multiple",
            "description": match[2].strip(),
            "exploit_scenario": "See description",
            "recommendation": match[3].strip()
        })
    
    # Parse gas optimizations
    opt_pattern = r'OPTIMIZATION \d+: (.+?)\s*Location: (.+?)\s*Technique: (.+?)\s*Savings: (.+?)(?=OPTIMIZATION|QUALITY|EXECUTIVE|$)'
    opt_matches = re.findall(opt_pattern, result_text, re.DOTALL | re.IGNORECASE)
    
    for match in opt_matches:
        gas_optimizations.append({
            "issue": match[0].strip(),
            "location": match[1].strip(),
            "current_cost": "N/A",
            "potential_savings": match[3].strip(),
            "technique": match[2].strip(),
            "example": ""
        })
    
    # Parse quality score
    score_match = re.search(r'QUALITY SCORE: (\d+)', result_text, re.IGNORECASE)
    if score_match:
        code_quality_score = int(score_match.group(1))
    
    # Parse recommendations
    rec_pattern = r'RECOMMENDATIONS?:(.+?)(?=COMPLIANCE|EXECUTIVE|$)'
    rec_match = re.search(rec_pattern, result_text, re.DOTALL | re.IGNORECASE)
    if rec_match:
        rec_text = rec_match.group(1)
        recs = re.findall(r'\d+\.\s*(.+?)(?=\d+\.|$)', rec_text, re.DOTALL)
        security_recommendations = [r.strip() for r in recs if r.strip()]
    
    # Calculate severity score
    critical_count = sum(1 for v in vulnerabilities if v['severity'].lower() == 'critical')
    high_count = sum(1 for v in vulnerabilities if v['severity'].lower() == 'high')
    severity_score = min(10, critical_count * 3 + high_count * 2 + len(vulnerabilities))
    
    return vulnerabilities, gas_optimizations, security_recommendations, code_quality_score, severity_score

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the frontend interface"""
    # Try to serve separate HTML file if it exists
    if os.path.exists("frontend.html"):
        return FileResponse("frontend.html")
    
    # Otherwise, return embedded HTML
    return HTMLResponse(content="<h1>Frontend not found</h1><p>Please create frontend.html file</p>")

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    try:
        gemini_configured = bool(os.getenv("GEMINI_API_KEY"))
        return HealthResponse(
            status="healthy",
            timestamp=datetime.now().isoformat(),
            gemini_configured=gemini_configured
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/audit", response_model=AuditResult)
async def audit_contract(submission: ContractSubmission):
    """Audit a smart contract using CrewAI agents"""
    try:
        print(f"\nStarting audit for: {submission.contract_name}")
        print(f"Language: {submission.contract_language}")
        print(f"Code length: {len(submission.contract_code)} characters\n")
        
        # Create and run the audit crew
        crew = create_audit_crew(submission.contract_code, submission.contract_language)
        result = crew.kickoff()
        
        print("\nCrew analysis complete!")
        
        # Parse results
        result_text = str(result)
        vulnerabilities, gas_optimizations, security_recommendations, code_quality_score, severity_score = parse_crew_output(result_text)
        
        print(f"\nResults Summary:")
        print(f"   - Vulnerabilities found: {len(vulnerabilities)}")
        print(f"   - Gas optimizations: {len(gas_optimizations)}")
        print(f"   - Quality score: {code_quality_score}/100")
        print(f"   - Severity score: {severity_score}/10\n")
        
        return AuditResult(
            contract_name=submission.contract_name,
            timestamp=datetime.now().isoformat(),
            severity_score=severity_score,
            vulnerabilities=vulnerabilities,
            gas_optimizations=gas_optimizations,
            security_recommendations=security_recommendations,
            code_quality_score=code_quality_score,
            detailed_report=result_text
        )
        
    except Exception as e:
        print(f"\nError during audit: {str(e)}\n")
        raise HTTPException(status_code=500, detail=f"Audit failed: {str(e)}")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print("\n" + "="*60)

    print("SMART CONTRACT SECURITY AUDITOR")
    print("="*60)
    print(f"Server starting on http://localhost:{port}")
    print(f"Gemini API configured: {bool(os.getenv('GEMINI_API_KEY'))}")
    print("="*60 + "\n")
    # uvicorn.run(app, host="0.0.0.0", port=port)
    if __name__ == "__main__":
        uvicorn.run(app)

    
