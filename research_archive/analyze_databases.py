#!/usr/bin/env python3
"""
Engine DJ Database Analysis Tool
=================================

Examines Engine DJ's SQLite databases to find encryption metadata,
stored keys, per-track encryption parameters, and stems-related configuration.

Target: Find how encryption keys are derived (UUID, track ID, account-based, etc.)
"""

import sqlite3
import os
import sys
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Any

class DatabaseAnalyzer:
    def __init__(self, database_dir: str):
        self.database_dir = Path(database_dir)
        self.databases = {}
        self.findings = {}
        
    def load_databases(self):
        """Load all SQLite databases from the directory."""
        print(f"Loading databases from: {self.database_dir}\n")
        
        for db_file in sorted(self.database_dir.glob("*.db")):
            try:
                conn = sqlite3.connect(str(db_file))
                # Enable foreign keys and other features
                conn.execute("PRAGMA foreign_keys = ON")
                self.databases[db_file.name] = conn
                print(f"✓ Loaded: {db_file.name}")
            except Exception as e:
                print(f"✗ Failed to load {db_file.name}: {e}")
        
        print(f"\nTotal databases loaded: {len(self.databases)}\n")
    
    def list_all_tables(self):
        """List all tables in all databases."""
        print("=" * 80)
        print("TABLE INVENTORY")
        print("=" * 80 + "\n")
        
        for db_name, conn in sorted(self.databases.items()):
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )
                tables = [row[0] for row in cursor.fetchall()]
                
                if tables:
                    print(f"{db_name}:")
                    for table in tables:
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        count = cursor.fetchone()[0]
                        print(f"  - {table} ({count} rows)")
                    print()
            except Exception as e:
                print(f"Error reading {db_name}: {e}\n")
    
    def inspect_table_schema(self, db_name: str, table_name: str) -> List[Tuple]:
        """Get schema info for a specific table."""
        try:
            cursor = self.databases[db_name].cursor()
            cursor.execute(f"PRAGMA table_info({table_name})")
            return cursor.fetchall()
        except Exception as e:
            print(f"Error inspecting {db_name}.{table_name}: {e}")
            return []
    
    def query_table_sample(self, db_name: str, table_name: str, limit: int = 5) -> List[Dict]:
        """Get sample rows from a table."""
        try:
            cursor = self.databases[db_name].cursor()
            cursor.execute(f"SELECT * FROM {table_name} LIMIT {limit}")
            
            # Get column names
            columns = [description[0] for description in cursor.description]
            
            # Fetch rows
            rows = []
            for row in cursor.fetchall():
                rows.append(dict(zip(columns, row)))
            
            return rows
        except Exception as e:
            print(f"Error querying {db_name}.{table_name}: {e}")
            return []
    
    def search_for_encryption_metadata(self):
        """Search for encryption-related data across all databases."""
        print("=" * 80)
        print("ENCRYPTION METADATA SEARCH")
        print("=" * 80 + "\n")
        
        keywords = [
            'key', 'salt', 'iv', 'encryption', 'crypto', 'cipher', 'hash',
            'xor', 'stem', 'protected', 'drm', 'token', 'secret', 'uuid'
        ]
        
        findings = []
        
        for db_name, conn in self.databases.items():
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            for table in tables:
                # Get columns
                cursor.execute(f"PRAGMA table_info({table})")
                columns = [row[1].lower() for row in cursor.fetchall()]
                
                # Check if any keyword is in column names
                matching_cols = [col for col in columns if any(kw in col for kw in keywords)]
                
                if matching_cols:
                    findings.append((db_name, table, matching_cols))
                    print(f"🔑 {db_name}/{table}")
                    print(f"   Encryption-related columns: {', '.join(matching_cols)}")
                    
                    # Show schema
                    schema = self.inspect_table_schema(db_name, table)
                    for col in schema:
                        print(f"      {col[1]} ({col[2]})")
                    
                    # Show samples
                    samples = self.query_table_sample(db_name, table, limit=3)
                    if samples:
                        print(f"   Sample rows:")
                        for sample in samples:
                            print(f"      {sample}")
                    print()
        
        if not findings:
            print("⚠ No encryption-related columns found in any database\n")
        
        return findings
    
    def search_for_stems_metadata(self):
        """Search for stems-specific metadata."""
        print("=" * 80)
        print("STEMS FILES METADATA SEARCH")
        print("=" * 80 + "\n")
        
        findings = []
        
        for db_name, conn in self.databases.items():
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            for table in tables:
                try:
                    # Try to find stems references
                    cursor.execute(f"SELECT * FROM {table} LIMIT 1")
                    columns = [description[0] for description in cursor.description]
                    
                    # Look for common file/path columns
                    file_cols = [col for col in columns if 'path' in col.lower() or 'file' in col.lower() or 'name' in col.lower()]
                    
                    if file_cols:
                        cursor.execute(f"SELECT * FROM {table}")
                        for row in cursor.fetchall():
                            row_dict = dict(zip(columns, row))
                            for col in file_cols:
                                if row_dict[col] and 'stem' in str(row_dict[col]).lower():
                                    findings.append((db_name, table, row_dict))
                            
                except Exception as e:
                    pass
        
        if findings:
            print(f"Found {len(findings)} stems-related records:\n")
            for db_name, table, record in findings[:10]:  # Limit to first 10
                print(f"{db_name}/{table}:")
                for key, value in record.items():
                    if value:
                        print(f"  {key}: {value}")
                print()
        else:
            print("⚠ No stems files found in metadata\n")
        
        return findings
    
    def analyze_uuid_patterns(self):
        """Look for UUID patterns that might relate to encryption."""
        print("=" * 80)
        print("UUID PATTERN ANALYSIS")
        print("=" * 80 + "\n")
        
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        import re
        
        found_uuids = {}
        
        for db_name, conn in self.databases.items():
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            for table in tables:
                try:
                    cursor.execute(f"SELECT * FROM {table}")
                    columns = [description[0] for description in cursor.description]
                    
                    for row in cursor.fetchall():
                        row_dict = dict(zip(columns, row))
                        for col, value in row_dict.items():
                            if value and isinstance(value, str):
                                matches = re.findall(uuid_pattern, str(value), re.IGNORECASE)
                                for uuid in matches:
                                    key = f"{db_name}/{table}/{col}"
                                    if key not in found_uuids:
                                        found_uuids[key] = []
                                    found_uuids[key].append(uuid)
                except Exception:
                    pass
        
        if found_uuids:
            print(f"Found {len(found_uuids)} columns with UUIDs:\n")
            for location, uuids in sorted(found_uuids.items()):
                unique_uuids = set(uuids)
                print(f"{location}: {len(unique_uuids)} unique")
                for uuid in sorted(unique_uuids)[:3]:
                    print(f"  - {uuid}")
                if len(unique_uuids) > 3:
                    print(f"  ... and {len(unique_uuids) - 3} more")
                print()
        else:
            print("⚠ No UUIDs found in any database\n")
        
        return found_uuids
    
    def deep_inspect_likely_tables(self):
        """Deep inspection of tables most likely to contain encryption metadata."""
        print("=" * 80)
        print("DEEP INSPECTION OF LIKELY TABLES")
        print("=" * 80 + "\n")
        
        # Tables likely to contain stems metadata: stm.db (stems?), trm.db (track?), m.db (main?)
        likely_dbs = ['stm.db', 'trm.db', 'm.db', 'itm.db']
        
        for db_name in likely_dbs:
            if db_name not in self.databases:
                continue
            
            print(f"\n{'=' * 60}")
            print(f"Detailed Analysis: {db_name}")
            print(f"{'=' * 60}\n")
            
            cursor = self.databases[db_name].cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            for table in tables:
                print(f"\n📊 Table: {table}")
                
                # Show schema
                schema = self.inspect_table_schema(db_name, table)
                print(f"   Columns ({len(schema)}):")
                for col_info in schema:
                    col_id, col_name, col_type, notnull, dflt, pk = col_info
                    print(f"      [{col_id}] {col_name}: {col_type}" + (" PK" if pk else ""))
                
                # Show row count
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                print(f"   Rows: {count}")
                
                # Show first few rows
                if count > 0:
                    cursor.execute(f"SELECT * FROM {table} LIMIT 3")
                    columns = [description[0] for description in cursor.description]
                    print(f"   Sample data:")
                    
                    for i, row in enumerate(cursor.fetchall(), 1):
                        row_dict = dict(zip(columns, row))
                        print(f"\n      Row {i}:")
                        for col, val in row_dict.items():
                            # Truncate long values
                            val_str = str(val)[:80] if val else "NULL"
                            print(f"         {col}: {val_str}")
    
    def close_all(self):
        """Close all database connections."""
        for conn in self.databases.values():
            conn.close()

def main():
    database_dir = "c:\\Users\\Daniel\\git\\engine-dj-stems-research\\database"
    
    if not os.path.exists(database_dir):
        print(f"Database directory not found: {database_dir}")
        sys.exit(1)
    
    analyzer = DatabaseAnalyzer(database_dir)
    
    try:
        analyzer.load_databases()
        analyzer.list_all_tables()
        analyzer.search_for_encryption_metadata()
        analyzer.search_for_stems_metadata()
        analyzer.analyze_uuid_patterns()
        analyzer.deep_inspect_likely_tables()
        
    finally:
        analyzer.close_all()
    
    print("\n" + "=" * 80)
    print("DATABASE ANALYSIS COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    main()
