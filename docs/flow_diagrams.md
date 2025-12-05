# GraphGuard - Visual Taint Flow Diagrams

## Diagram 1: Buffer Overflow via strcpy (CWE-121)


flowchart TD
A[[SOURCE
gets(input)
Line 13
vuln_buffer_overflow_strcpy.c]] --> B[[TAINTED
input
user controlled string, unbounded]]
B --> C[[PROPAGATED TO
user_input]]
C --> D[[SINK
strcpy(buffer, user_input)
Line 7
No bounds checking]]
style A fill:#ff9999
style D fill:#ff9999
classDef verdict fill:#ffcccc
E[VERDICT: CRITICAL VULNERABILITY
CWE-121: Stack-based Buffer Overflow
Attack Vector: Input longer than buffer size causes overflow]:::verdict



## Diagram 2: Command Injection via system (CWE-78)

flowchart TD
A[[SOURCE
scanf("%99s", file)
Line 13
vuln_command_injection.c]] --> B[[TAINTED
file
user controlled input]]
B --> C[[PROPAGATED TO
filename]]
C --> D[[SINK #1
sprintf(command, "cat %s", filename)
Line 7
Taint spreads to command variable]]
D --> E[[SINK #2
system(command)
Line 8
Executes tainted command string]]
style A fill:#ff9999
style D fill:#ff9999
style E fill:#ff9999
classDef verdict fill:#ffcccc
F[VERDICT: CRITICAL VULNERABILITY
CWE-78: OS Command Injection
Attack Vector: file = "; rm -rf /" executes malicious command]:::verdict


## Diagram 3: Buffer Overflow via sprintf (CWE-134)

flowchart TD
A[[SOURCE
scanf("%99s", name)
Line 12
vuln_buffer_overflow_sprintf.c]] --> B[[TAINTED
name
user controlled, max 99 chars]]
B --> C[[PROPAGATED TO
username]]
C --> D[[SINK
sprintf(message, "Welcome, %s!", username)
Line 6
No buffer size limit on message]]
style A fill:#ff9999
style D fill:#ff9999
classDef verdict fill:#ffcccc
E[VERDICT: HIGH SEVERITY VULNERABILITY
CWE-134: Uncontrolled Format String
Attack Vector: Long input overflows message buffer]:::verdict


## Diagram 4: Comparison - Pattern-Based vs Taint Analysis

flowchart LR
subgraph PATTERN ["PATTERN-BASED DETECTION"]
P1[Method: Flag all calls to dangerous functions]
P2[Flags: strcpy, sprintf, system, gets]
P3[Total Alerts: 5]
P4[Precision: 80%]
P5[X No data flow information]
P6[X Cannot distinguish safe vs unsafe usage]
P7[X High false positive rate]
end


subgraph TAINT ["TAINT ANALYSIS DETECTION"]
    T1[Method: Track data flow from sources to sinks]
    T2[Tracks: scanf/gets -> variable -> dangerous_function]
    T3[True Vulnerabilities: 4 unique flows]
    T4[Precision: 100%]
    T5[OK Shows exact data flow path]
    T6[OK Provides source and sink line numbers]
    T7[OK Identifies tainted variables]
    T8[OK Eliminates false positives]
end

IMPROVEMENT[IMPROVEMENT: 20% precision increase]
PATTERN --> IMPROVEMENT
TAINT --> IMPROVEMENT
style PATTERN fill:#ffe6cc
style TAINT fill:#ccffcc





## Summary Table

| Vulnerability      | Source          | Tainted Variable     | Sink              | CWE     |
|--------------------|-----------------|----------------------|-------------------|---------|
| Buffer Overflow    | gets() line 13  | input → user_input   | strcpy() line 7   | CWE-121 |
| Command Injection  | scanf() line 13 | file → filename      | system() line 8   | CWE-78  |
| Format String      | scanf() line 12 | name → username      | sprintf() line 6  | CWE-134 | [web:9][web:10]
