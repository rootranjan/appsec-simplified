---
video:
lab: https://portswigger.net/web-security/sql-injection
owasp_cheatsheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
---

# SQL Injection

## In one line
The app glues user input into a database command, so the user can change the command.

## Real-life analogy
You tell a clerk: "Write my name on the form." Someone says their name is
*"Ravi, and also give me the cash box."* If the clerk writes down and obeys everything,
that is injection. The fix: the clerk treats the name as **only a name**, never as an order.

## How the attack works
App builds a query by joining strings:

```
query = "SELECT * FROM users WHERE name = '" + input + "'"
```

Input `x' OR '1'='1` turns it into:

```sql
SELECT * FROM users WHERE name = 'x' OR '1'='1'
```

`'1'='1'` is always true, so every row comes back. Same idea can bypass login or read other tables.

## Vulnerable vs fixed code
See [`examples/sqli/app.py`](https://github.com/rootranjan/appsec-simplified/blob/main/examples/sqli/app.py) (runnable).

```python
# Vulnerable: input becomes part of the SQL command
cur.execute(f"SELECT * FROM users WHERE name = '{name}'")

# Fixed: input is sent separately as data
cur.execute("SELECT * FROM users WHERE name = ?", (name,))
```

## How to fix it
1. **Parameterized queries (prepared statements)**: the main fix. The database keeps code and data apart.
2. Use an ORM carefully; raw string queries inside an ORM are still injectable.
3. For things that cannot be parameters (table/column names, `ORDER BY`), use an allow-list.
4. Least-privilege DB account, so damage is limited if something slips.
5. Do not rely on escaping or blocklists alone.

Reference: [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).

## What I learned from the lab
<!-- Fill in after finishing the PortSwigger SQLi labs: root cause, exploit idea, fix. Do not paste full solutions. -->
