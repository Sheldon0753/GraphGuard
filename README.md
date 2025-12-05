# GraphGuard

A Code Property Graph-Based Vulnerability Detection System Using Taint Analysis in Neo4j

GraphGuard detects security vulnerabilities in C/C++ code by tracking data flow from untrusted sources (like scanf) to dangerous sinks (like strcpy). Unlike pattern-based detection that flags all dangerous function calls, GraphGuard only reports vulnerabilities where untrusted data actually reaches dangerous operations.

---

## Key Results

| Metric | Pattern-Based | Taint Analysis |
|--------|---------------|----------------|
| Precision | 80% | 100% |
| False Positives | 1 | 0 |
| Shows Data Flow | No | Yes |
| Tainted Variable | No | Yes |

Taint analysis provides a 20 percentage point improvement in precision with zero false positives.

---

## System Architecture


C/C++ Source Files
|
v
+-------------------+
| Fraunhofer CPG | <- Parses code into Code Property Graph
+-------------------+
|
v
+-------------------+
| Neo4j | <- Stores graph with DFG edges
+-------------------+
|
v
+-------------------+
| Taint Analyzer | <- Python queries for source to sink flows
+-------------------+
|
v
Vulnerability Report


---

## Prerequisites

- Docker
- Python 3.8 or higher
- Java 21 (for CPG library)
- Git

---

## Installation and Setup

### Step 1: Clone Repository

```bash
git clone https://github.com/Sheldon0753/GraphGuard.git
cd GraphGuard

###Step 2: Start Neo4j Database
Bash

docker run -d \
  --name graphguard-neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  -e NEO4JLABS_PLUGINS='["apoc"]' \
  neo4j:5.14
Wait 30 seconds for Neo4j to start. Verify by opening http://localhost:7474 in your browser.


###Step 3: Install Python Dependencies
Bash

pip install neo4j

###Step 4: Build CPG Tool (First Time Only)
Bash

git clone https://github.com/Fraunhofer-AISEC/cpg.git
cd cpg/cpg-neo4j
../gradlew installDist
cd ../..

###Step 5: Import Test Files into Neo4j
Bash

./cpg/cpg-neo4j/build/install/cpg-neo4j/bin/cpg-neo4j \
  --host=localhost \
  --port=7687 \
  --user=neo4j \
  --password=password \
  test_files/vuln_*.c


###Step 6: Run Taint Analysis
Bash

python3 src/taint_analyzer.py


Repository Structure
text

GraphGuard/
|-- README.md
|-- docs/
|   |-- flow_diagrams.md
|-- src/
|   |-- taint_analyzer.py
|   |-- simple_taint.py
|-- test_files/
|   |-- vuln_buffer_overflow_strcpy.c
|   |-- vuln_buffer_overflow_sprintf.c
|   |-- vuln_command_injection.c
|   |-- vuln_integer_overflow.c
|-- screenshots/
|   |-- screenshot_01_database_overview.png
|   |-- screenshot_02_function_calls.png
|   |-- screenshot_03_taint_flows.png
|   |-- screenshot_04_graph_visual.png
|   |-- screenshot_05_taint_analyzer_output.png
|   |-- screenshot_06_comparison_metrics.png
|-- results/
    |-- taint_analysis_results.txt


How Taint Analysis Works
Taint Sources (Untrusted Input)
Function	Risk	Description
scanf()	HIGH	Console input
gets()	CRITICAL	No bounds checking
fgets()	MEDIUM	Bounded but external
getenv()	HIGH	Environment variables
Taint Sinks (Dangerous Operations)
Function	Vulnerability	CWE
strcpy()	Buffer Overflow	CWE-121
sprintf()	Format String	CWE-134
system()	Command Injection	CWE-78
strcat()	Buffer Overflow	CWE-121

Core Query

The taint analysis uses this Cypher query to find vulnerability paths:

cypher

MATCH p=(source:CallExpression)
      -[:ARGUMENTS|DFG*1..5]-(ref:Reference)
      -[:DFG*1..5]-(sink:CallExpression)
WHERE source.name IN ['scanf', 'gets', 'fgets']
  AND sink.name IN ['strcpy', 'sprintf', 'system']
RETURN source.name as Source,
       ref.name as TaintedVariable,
       sink.name as Sink,
       source.startLine as SourceLine,
       sink.startLine as SinkLine


Example Output
text

======================================================================
GRAPHGUARD TAINT ANALYSIS REPORT
======================================================================

[1] TAINT SOURCES FOUND (User Input):
----------------------------------------------------------------------
   scanf() at line 12
   gets() at line 13
   scanf() at line 13

[2] TAINT FLOW ANALYSIS (Source -> Variable -> Sink):
----------------------------------------------------------------------

   VULNERABILITY #1:
      SOURCE: gets() at line 13
         Code: gets(input);
      TAINTED VARIABLE: 'user_input'
      SINK: strcpy() at line 7
         Code: strcpy(buffer, user_input);
      RISK: HIGH - Buffer Overflow (CWE-121)

   VULNERABILITY #2:
      SOURCE: scanf() at line 13
         Code: scanf("%99s", file);
      TAINTED VARIABLE: 'filename'
      SINK: system() at line 8
         Code: system(command);
      RISK: CRITICAL - Command Injection (CWE-78)

[3] COMPARISON METRICS:
----------------------------------------------------------------------
   Taint Analysis Precision: 100%
   Pattern-Based Precision: 80%
   Improvement: 20 percentage points
======================================================================

Visual Flow Diagrams

Buffer Overflow (CWE-121)
text

+---------------------------------------------+
|  [SOURCE] gets(input)         Line 13       |
|              |                              |
|              v                              |
|  [TAINTED] input -> user_input              |
|              |                              |
|              v                              |
|  [SINK] strcpy(buffer, user_input) Line 7   |
|                                             |
|  CRITICAL: Stack-based Buffer Overflow      |
+---------------------------------------------+


Command Injection (CWE-78)
text

+---------------------------------------------+
|  [SOURCE] scanf(file)         Line 13       |
|              |                              |
|              v                              |
|  [TAINTED] file -> filename                 |
|              |                              |
|              v                              |
|  [INTERMEDIATE] sprintf(command, filename)  |
|              |                              |
|              v                              |
|  [SINK] system(command)       Line 8        |
|                                             |
|  CRITICAL: OS Command Injection             |
|  Attack: file="; rm -rf /"                  |
+---------------------------------------------+

Neo4j Queries Reference

Check Database Contents
cypher

MATCH (n) 
RETURN labels(n)[0] as Type, count(*) as Count 
ORDER BY Count DESC

Find All Function Calls
cypher

MATCH (c:CallExpression)
RETURN c.name as Function, c.code as Code
ORDER BY c.name

Pattern-Based Detection (Baseline)
cypher

MATCH (c:CallExpression)
WHERE c.name IN ['strcpy', 'sprintf', 'system', 'gets']
RETURN c.name, c.code, c.startLine

Taint Flow Detection
cypher

MATCH (source:CallExpression)-[:ARGUMENTS|DFG*1..5]-(ref:Reference)-[:DFG*1..5]-(sink:CallExpression)
WHERE source.name IN ['scanf', 'gets']
  AND sink.name IN ['strcpy', 'sprintf', 'system']
RETURN source.name as Source, ref.name as TaintedVar, sink.name as Sink

References
Fraunhofer CPG Library: https://github.com/Fraunhofer-AISEC/cpg
Neo4j Graph Database: https://neo4j.com/
NIST Juliet Test Suite: https://samate.nist.gov/SARD/
CWE - Common Weakness Enumeration: https://cwe.mitre.org/
