#!/usr/bin/env python3
"""
Analyze Engine DJ database for encryption keys or stem metadata
"""

import sqlite3
import sys

db_path = "m_library.db"

try:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    print("[*] Connected to Engine DJ database")
    print("[*] Analyzing schema...\n")
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    print(f"[*] Found {len(tables)} tables:\n")
    
    for table in tables:
        table_name = table[0]
        
        # Get column info
        cursor.execute(f"PRAGMA table_info({table_name});")
        columns = cursor.fetchall()
        
        # Get row count
        cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
        count = cursor.fetchone()[0]
        
        print(f"\n[*] Table: {table_name} ({count} rows)")
        print(f"    Columns:")
        for col in columns:
            cid, name, type_, notnull, dflt_value, pk = col
            print(f"      - {name} ({type_})")
        
        # If table is small, show first few rows
        if count > 0 and count <= 10:
            cursor.execute(f"SELECT * FROM {table_name} LIMIT 3;")
            rows = cursor.fetchall()
            print(f"    Sample data:")
            for row in rows[:3]:
                print(f"      {dict(row)}")
    
    # Search for key-like strings in all tables
    print("\n\n[*] Searching for encryption keys or stems metadata...\n")
    
    for table in tables:
        cursor.execute(f"PRAGMA table_info({table});")
        columns = cursor.fetchall()
        
        for col in columns:
            col_name = col[1]
            col_type = col[2]
            
            # Look for interesting columns
            if any(keyword in col_name.lower() for keyword in ['key', 'secret', 'crypt', 'stems', 'aes', 'iv', 'salt']):
                print(f"[+] Found interesting column: {table}.{col_name} ({col_type})")
                try:
                    cursor.execute(f"SELECT DISTINCT {col_name} FROM {table} LIMIT 5;")
                    results = cursor.fetchall()
                    for res in results:
                        val = res[0]
                        if val:
                            print(f"    Value: {repr(val)[:100]}")
                except:
                    pass
    
    conn.close()
    
except Exception as e:
    print(f"[!] Error: {e}")
    sys.exit(1)
