#!/usr/bin/env python3
"""
Fast Engine DJ Database Analysis - Search for Stems Encryption Keys
Optimized to avoid slow queries on large tables
"""

import sqlite3
import os
import sys

def analyze_database(db_path):
    """Analyze a single database file"""
    print(f"\n{'='*80}")
    print(f"Analyzing: {os.path.basename(db_path)}")
    print('='*80)
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [row[0] for row in cursor.fetchall()]
    
    print(f"\n📋 Tables ({len(tables)}):")
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"  - {table}: {count:,} rows")
    
    # Look for stems-related tables
    stems_tables = [t for t in tables if 'stem' in t.lower()]
    if stems_tables:
        print(f"\n🎵 Stems-related tables: {', '.join(stems_tables)}")
        for table in stems_tables:
            print(f"\n  Table: {table}")
            cursor.execute(f"PRAGMA table_info({table})")
            columns = cursor.fetchall()
            print(f"  Columns: {', '.join([col[1] for col in columns])}")
            
            # Sample first few rows
            cursor.execute(f"SELECT * FROM {table} LIMIT 5")
            rows = cursor.fetchall()
            if rows:
                print(f"  Sample data (first 5 rows):")
                col_names = [col[1] for col in columns]
                for row in rows:
                    print(f"    {dict(zip(col_names, row))}")
    
    # Search for UUID patterns in Track table (limited)
    if 'Track' in tables:
        print(f"\n🎯 Searching Track table for UUID '0f7da717'...")
        cursor.execute("PRAGMA table_info(Track)")
        track_columns = [col[1] for col in cursor.fetchall()]
        print(f"  Track columns: {', '.join(track_columns)}")
        
        # Search for our specific UUID
        cursor.execute("SELECT * FROM Track WHERE id LIKE '%0f7da717%' OR path LIKE '%0f7da717%' LIMIT 10")
        rows = cursor.fetchall()
        if rows:
            print(f"  ✅ Found {len(rows)} tracks matching UUID:")
            for row in rows:
                print(f"    {dict(zip(track_columns, row))}")
        else:
            print("  ❌ No tracks found with UUID '0f7da717'")
    
    # Search for encryption-related columns in all tables (fast check)
    print(f"\n🔐 Searching for encryption-related columns...")
    encryption_keywords = ['key', 'salt', 'hash', 'encrypt', 'cipher', 'token', 'secret']
    found_columns = []
    
    for table in tables:
        cursor.execute(f"PRAGMA table_info({table})")
        columns = cursor.fetchall()
        for col in columns:
            col_name = col[1].lower()
            if any(keyword in col_name for keyword in encryption_keywords):
                found_columns.append((table, col[1], col[2]))  # table, column, type
    
    if found_columns:
        print("  ✅ Found potentially interesting columns:")
        for table, col, col_type in found_columns:
            print(f"    - {table}.{col} ({col_type})")
            # Sample values (limit to avoid slow queries)
            cursor.execute(f"SELECT DISTINCT {col} FROM {table} WHERE {col} IS NOT NULL LIMIT 10")
            values = cursor.fetchall()
            if values:
                print(f"      Sample values: {[v[0] for v in values[:3]]}")
    else:
        print("  ❌ No obvious encryption-related columns found")
    
    # Check Information table for metadata
    if 'Information' in tables:
        print(f"\n📊 Information table:")
        cursor.execute("SELECT * FROM Information")
        rows = cursor.fetchall()
        cursor.execute("PRAGMA table_info(Information)")
        columns = [col[1] for col in cursor.fetchall()]
        for row in rows:
            print(f"  {dict(zip(columns, row))}")
    
    conn.close()


def main():
    db_dir = os.path.join(os.path.dirname(__file__), 'database')
    
    if not os.path.exists(db_dir):
        print(f"❌ Database directory not found: {db_dir}")
        sys.exit(1)
    
    print("Engine DJ Database Analysis - Fast Edition")
    print("Searching for stems encryption keys/metadata")
    
    # Analyze m.db (main database)
    main_db = os.path.join(db_dir, 'm.db')
    analyze_database(main_db)
    
    # Check for other .db files
    other_dbs = [f for f in os.listdir(db_dir) if f.endswith('.db') and f != 'm.db']
    if other_dbs:
        print(f"\n\n📁 Found additional database files: {', '.join(other_dbs)}")
        for db_file in other_dbs:
            analyze_database(os.path.join(db_dir, db_file))
    
    print("\n" + "="*80)
    print("Analysis complete!")
    print("="*80)


if __name__ == '__main__':
    main()
