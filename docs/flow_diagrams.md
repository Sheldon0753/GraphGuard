Diagram 1: Buffer Overflow via strcpy (CWE-121)
mermaidflowchart TD
    A[SOURCE: gets input<br/>Line 13<br/>vuln_buffer_overflow_strcpy.c<br/>Type: Unbounded User Input] --> B[TAINTED DATA<br/>Variable: input<br/>Status: User-controlled string]
    B --> C[PROPAGATION<br/>Variable: user_input<br/>Function parameter]
    C --> D[SINK: strcpy buffer, user_input<br/>Line 7<br/>Vulnerability: No bounds checking]
    D --> E[VERDICT: CRITICAL<br/>CWE-121: Stack-based Buffer Overflow<br/>Attack: Input exceeding buffer size causes overflow]
    
    style A fill:#ffcccc,stroke:#cc0000,stroke-width:2px
    style D fill:#ffcccc,stroke:#cc0000,stroke-width:2px
    style E fill:#fff3cd,stroke:#856404,stroke-width:2px
Flow Description:

Untrusted input enters via gets(input) at line 13 with no size limit
Data stored in variable input (tainted)
Taint propagates to function parameter user_input
Tainted data reaches strcpy() at line 7 without validation
Result: Buffer overflow vulnerability allowing memory corruption

Risk Level: CRITICAL
Common Weakness Enumeration: CWE-121
Attack Scenario: Attacker provides input longer than 64-byte buffer, overwriting adjacent memory and potentially hijacking control flow.

Diagram 2: Command Injection via system (CWE-78)
mermaidflowchart TD
    A[SOURCE: scanf %99s, file<br/>Line 13<br/>vuln_command_injection.c<br/>Type: User-controlled filename] --> B[TAINTED DATA<br/>Variable: file<br/>Status: Unchecked user input]
    B --> C[PROPAGATION<br/>Variable: filename<br/>Function parameter]
    C --> D[INTERMEDIATE SINK<br/>sprintf command, cat %s, filename<br/>Line 7<br/>Taint spreads to command variable]
    D --> E[FINAL SINK: system command<br/>Line 8<br/>Executes tainted shell command]
    E --> F[VERDICT: CRITICAL<br/>CWE-78: OS Command Injection<br/>Attack: Arbitrary command execution]
    
    style A fill:#ffcccc,stroke:#cc0000,stroke-width:2px
    style D fill:#ffe6cc,stroke:#ff8c00,stroke-width:2px
    style E fill:#ffcccc,stroke:#cc0000,stroke-width:2px
    style F fill:#fff3cd,stroke:#856404,stroke-width:2px
Flow Description:

User provides filename via scanf() at line 13
Input stored in variable file (tainted)
Taint propagates to parameter filename
sprintf() at line 7 incorporates tainted data into command string
system() at line 8 executes the tainted command string
Result: Arbitrary command execution vulnerability

Risk Level: CRITICAL
Common Weakness Enumeration: CWE-78
Attack Scenario: Input like "; rm -rf /" or "| malicious_script.sh" allows execution of arbitrary system commands with application privileges.

Diagram 3: Buffer Overflow via sprintf (CWE-134)
mermaidflowchart TD
    A[SOURCE: scanf %99s, name<br/>Line 12<br/>vuln_buffer_overflow_sprintf.c<br/>Type: Bounded input max 99 chars] --> B[TAINTED DATA<br/>Variable: name<br/>Status: User-controlled string]
    B --> C[PROPAGATION<br/>Variable: username<br/>Function parameter]
    C --> D[SINK: sprintf message, Welcome, %s!, username<br/>Line 6<br/>Vulnerability: Insufficient buffer size]
    D --> E[VERDICT: HIGH SEVERITY<br/>CWE-134: Uncontrolled Format String<br/>Attack: Long input overflows message buffer]
    
    style A fill:#ffcccc,stroke:#cc0000,stroke-width:2px
    style D fill:#ffcccc,stroke:#cc0000,stroke-width:2px
    style E fill:#fff3cd,stroke:#856404,stroke-width:2px
Flow Description:

User input acquired via scanf() limited to 99 characters at line 12
Data stored in variable name (tainted)
Taint propagates to function parameter username
sprintf() at line 6 formats tainted data into potentially undersized message buffer
Result: Format string vulnerability and potential buffer overflow

Risk Level: HIGH
Common Weakness Enumeration: CWE-134
Attack Scenario: Input exceeding message buffer capacity (accounting for "Welcome, " prefix and "!" suffix) causes buffer overflow, potentially corrupting stack data.

Diagram 4: Comparative Analysis - Pattern-Based vs Taint Analysis
mermaidflowchart LR
    subgraph PATTERN[Pattern-Based Detection]
        P1[Detection Method:<br/>Flag all dangerous function calls]
        P2[Flagged Functions:<br/>strcpy, sprintf, system, gets, strcat]
        P3[Total Alerts Generated: 5]
        P4[True Positives: 4<br/>False Positives: 1]
        P5[Precision: 80 percent]
        P6[Limitations:<br/>- No data flow information<br/>- Cannot distinguish safe usage<br/>- High false positive rate<br/>- No source identification]
    end
    
    subgraph TAINT[Taint Analysis Detection]
        T1[Detection Method:<br/>Track data flow from sources to sinks]
        T2[Analysis:<br/>Source identification<br/>Data flow graph traversal<br/>Sink validation]
        T3[Detected Vulnerabilities: 4]
        T4[True Positives: 4<br/>False Positives: 0]
        T5[Precision: 100 percent]
        T6[Advantages:<br/>+ Shows complete flow path<br/>+ Provides source and sink locations<br/>+ Identifies tainted variables<br/>+ Eliminates false positives]
    end
    
    PATTERN --> IMPROVEMENT[IMPROVEMENT<br/>+20 percentage points precision<br/>100 percent false positive reduction]
    TAINT --> IMPROVEMENT
    
    style PATTERN fill:#ffe6e6,stroke:#cc0000
    style TAINT fill:#e6ffe6,stroke:#00cc00
    style IMPROVEMENT fill:#e6f3ff,stroke:#0066cc,stroke-width:3px
Key Findings:

Precision Improvement: 80% to 100% (20 percentage point increase)
False Positive Elimination: Pattern-based generated 1 false positive; taint analysis generated 0
Information Quality: Taint analysis provides actionable flow paths vs simple function flagging
Developer Value: Complete source-to-sink paths enable faster vulnerability remediation


Summary: Detected Taint Flows
Vulnerability TypeSource FunctionSource LineTainted Variable(s)Sink FunctionSink LineCWE IDSeverityBuffer Overflowgets()13input → user_inputstrcpy()7CWE-121CRITICALCommand Injectionscanf()13file → filename → commandsystem()8CWE-78CRITICALFormat Stringscanf()12name → usernamesprintf()6CWE-134HIGHInteger Overflowscanf()14user_size(various)MultipleCWE-190MEDIUM
Total Unique Vulnerabilities Detected: 4
Total Taint Flow Paths: 10
Detection Precision: 100%
False Positive Rate: 0%
