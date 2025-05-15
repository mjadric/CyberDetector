#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DDoS Defender - PostgreSQL Connection Module
Centralno mjesto za upravljanje konekcijom s PostgreSQL bazom
"""

import os
import logging

# Logger
logger = logging.getLogger("postgres_connection")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Provjera je li psycopg2 dostupan
try:
    import psycopg2
    from psycopg2 import pool
    from psycopg2.extras import RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    logger.warning("PostgreSQL support not available - psycopg2 not installed")

# Globalna konekcija i pool
_pg_pool = None

def get_postgres_connection():
    """
    Vraća konekciju na PostgreSQL bazu podataka.
    
    Returns:
        connection: Konekcija na PostgreSQL ili None ako konekcija nije uspjela
    """
    global _pg_pool
    
    if not POSTGRES_AVAILABLE:
        logger.warning("PostgreSQL support not available")
        return None
    
    try:
        # Ako već imamo pool, vrati konekciju iz poola
        if _pg_pool is not None:
            return _pg_pool.getconn()
        
        # Dohvati DATABASE_URL iz environment varijable
        database_url = os.environ.get("DATABASE_URL")
        
        if not database_url:
            # Pokušaj sastaviti iz PG* varijabli
            pg_host = os.environ.get("PGHOST")
            pg_port = os.environ.get("PGPORT")
            pg_db = os.environ.get("PGDATABASE")
            pg_user = os.environ.get("PGUSER")
            pg_password = os.environ.get("PGPASSWORD")
            
            if pg_host and pg_port and pg_db and pg_user and pg_password:
                database_url = f"postgresql://{pg_user}:{pg_password}@{pg_host}:{pg_port}/{pg_db}"
                logger.info(f"Created connection URL from PG* variables to host: {pg_host}")
            else:
                logger.error("No PostgreSQL connection details found in environment variables")
                return None
        
        # Maskiraj korisničko ime i lozinku u URI za logove
        display_url = database_url
        if "@" in display_url:
            # Format: postgresql://user:pass@host:port/dbname
            protocol, rest = display_url.split("://", 1)
            user_pass, host_port_db = rest.split("@", 1)
            display_url = f"{protocol}://***:***@{host_port_db}"
            
        logger.info(f"Connecting to PostgreSQL at: {display_url}")
        
        # Stvori konekcijski pool
        _pg_pool = pool.ThreadedConnectionPool(1, 10, database_url)
        
        # Vrati konekciju iz poola
        conn = _pg_pool.getconn()
        
        # Provjeri konekciju
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        
        logger.info("PostgreSQL connection successful")
        
        return conn
    except Exception as e:
        logger.error(f"PostgreSQL connection failed: {e}")
        return None

def close_postgres_connection(conn):
    """
    Vraća konekciju u pool.
    
    Args:
        conn: Konekcija za vratiti u pool
    """
    global _pg_pool
    
    if _pg_pool is not None and conn is not None:
        try:
            _pg_pool.putconn(conn)
        except Exception as e:
            logger.error(f"Error returning connection to pool: {e}")

def close_postgres_pool():
    """
    Zatvara konekcijski pool.
    """
    global _pg_pool
    
    if _pg_pool is not None:
        try:
            _pg_pool.closeall()
            logger.info("PostgreSQL connection pool closed")
        except Exception as e:
            logger.error(f"Error closing connection pool: {e}")
        finally:
            _pg_pool = None