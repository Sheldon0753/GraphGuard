#!/usr/bin/env python3
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "00000000"))

print("\n" + "="*70)
print("GRAPHGUARD VULNERABILITY DETECTION COMPARISON")
print("="*70)

with driver.session() as session:
    
    print("\n[1] ALL FUNCTION CALLS IN CODE:")
    print("-" * 50)
    result = session.run("""
        MATCH (c:CallExpression)
        RETURN c.name as Function, c.code as Code
        ORDER BY c.name
    """)
    
    calls = list(result)
    for call in calls[:10]:
        print(f"  {call['Function']}: {call['Code'][:50]}")
    
    print("\n[2] PATTERN-BASED DETECTION:")
    print("-" * 50)
    result = session.run("""
        MATCH (c:CallExpression)
        WHERE c.name IN ['strcpy', 'sprintf', 'system', 'gets', 'strcat']
        RETURN c.name as Vuln, c.code as Code
    """)
    
    pattern_vulns = list(result)
    print(f"  Flagged {len(pattern_vulns)} dangerous functions:")
    for v in pattern_vulns:
        print(f"     - {v['Vuln']}: {v['Code']}")
    
    print("\n[3] DATA FLOW CONNECTIONS:")
    print("-" * 50)
    result = session.run("""
        MATCH p=(n1)-[:DFG]->(n2)
        WHERE (n1:CallExpression OR n2:CallExpression)
        RETURN labels(n1)[0] as FromType, n1.name as From, 
               labels(n2)[0] as ToType, n2.name as To
        LIMIT 10
    """)
    
    flows = list(result)
    if flows:
        print("  Found data flows:")
        for f in flows:
            print(f"     {f['FromType']}: {f['From']} -> {f['ToType']}: {f['To']}")
    else:
        print("  No direct DFG edges between CallExpressions")
    
    print("\n[4] AVAILABLE RELATIONSHIPS:")
    print("-" * 50)
    result = session.run("""
        MATCH (c:CallExpression)-[r]-()
        RETURN DISTINCT type(r) as RelType, count(*) as Count
        ORDER BY Count DESC
    """)
    
    rels = list(result)
    print("  CallExpression nodes have these relationships:")
    for r in rels:
        print(f"     {r['RelType']}: {r['Count']}")

print("\n" + "="*70)

driver.close()
