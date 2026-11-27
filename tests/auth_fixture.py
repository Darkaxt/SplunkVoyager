"""A small entity-mapper dump in the formats of the real logs (invented names), for auth_analysis tests."""
import json
from pathlib import Path


def _db(ts, user, code, ip, port, db="PAYDB_01_P", cdb="CDB01", cluster="dbclu1.example", host="apphost1.example", extra=""):
    return (f'{ts}.123, PRECISE_TIMESTAMP="{ts}.123456", OS_USERNAME="oracle", USERNAME="{user}", USERHOST="{host}", '
            f'ACTION="100", ACTION_NAME="LOGON", COMMENT_TEXT="Authenticated by: DATABASE;AUTHENTICATED IDENTITY: {user}; '
            f'Client address: (ADDRESS=(PROTOCOL=tcp)(HOST={ip})(PORT={port})){extra}", SESSIONID="1", ENTRYID="1", '
            f'STATEMENTID="1", RETURNCODE="{code}", INSTANCE_NUMBER="1", OS_PROCESS="1", DBID="42", CLUSTER_NAME="{cluster}", '
            f'DB_NAME="{db}", CDB_NAME="{cdb}", DG_NAME="X", IS_NAME="X", DB_VERSION="19"')


def _txt(ts, action, user, status, addr="", priv="NONE"):
    return (f"{ts}\nLENGTH : '300'\nACTION :[{len(action)}] '{action}'\nDATABASE USER:[{len(user)}] '{user}'\n"
            f"PRIVILEGE :[{len(priv)}] '{priv}'\nCLIENT USER:[6] 'oracle'\nCLIENT TERMINAL:[0] ''\n"
            f"STATUS:[{len(status)}] '{status}'\nDBID:[2] '42'\nUSERHOST:[16] 'apphost1.example'\n"
            f"CLIENT ADDRESS:[{len(addr)}] '{addr}'\nACTION NUMBER:[3] '100'\n")


def build(case):
    seeds = Path(case) / "entities" / "seeds"
    ev = {"oracle:audit:db": [], "oracle:audit:text": [], "oracle:listener:xml": [], "oracle:alert:xml": [],
          "XmlWinEventLog": [], "linux_secure": []}

    def add(st, iso, raw, host="dbclu1.example"):
        ev[st].append({"_time": iso, "_raw": raw, "sourcetype": st, "host": host, "index": "x"})

    # brute force on BS_APP from 10.9.8.7: 3 invalid, 2 locked, then a success after the lock
    for i, (code, mm) in enumerate([(1017, "00"), (1017, "01"), (1017, "02"), (28000, "03"), (28000, "04"), (0, "30")]):
        add("oracle:audit:db", f"2026-11-26T08:{mm}:00.123+00:00", _db(f"2026-11-26 09:{mm}:00", "BS_APP", code, "10.9.8.7", 5000 + i))
    # spraying: 5 accounts, one failure each, same source, within 2 minutes
    for i in range(5):
        add("oracle:audit:db", f"2026-11-26T10:0{i // 2}:{10 + i % 2 * 20:02d}.000+00:00",
            _db(f"2026-11-26 11:0{i // 2}:{10 + i % 2 * 20:02d}", f"USR{i}", 1017, "10.9.8.7", 6000 + i))
    # an ordinary logon through a database link, and the LOGOFF that must be ignored
    add("oracle:audit:db", "2026-11-26T04:00:56.746+00:00", _db("2026-11-26 05:00:56", "SVC_LINK", 0, "10.1.1.1", 7000,
        extra="; DBLINK_INFO: (SOURCE_GLOBAL_NAME=SRC01, SOURCE_DB_NAME=HRDB_01_A, DBLINK_NAME=PAY.EXAMPLE, SOURCE_AUDIT_SESSIONID=9)"))
    add("oracle:audit:db", "2026-11-26T04:01:38.999+00:00", _db("2026-11-26 05:01:38", "SVC_LINK", 0, "10.1.1.1", 7000)
        .replace('ACTION="100", ACTION_NAME="LOGON"', 'ACTION="101", ACTION_NAME="LOGOFF"'))
    # OS audit: a SQL statement whose text holds STATUS:[4] '1017' and LOCKED_BY (must not count), a SYS CONNECT, a failed CONNECT
    sql = "select substrb(\"LOCKED_BY\",1,64) from t where x = 'a'\nSTATUS:[4] '1017'\nend"
    add("oracle:audit:text", "2026-11-26T02:32:40.000+00:00", _txt("Thu Nov 26 03:32:40 2026 +01:00", sql, "/", "0", priv="SYSDBA")
        .replace("ACTION NUMBER:[3] '100'", "ACTION NUMBER:[1] '3'"), host="dbhost9.example")
    add("oracle:audit:text", "2026-11-26T03:14:45.000+00:00", _txt("Thu Nov 26 04:14:45 2026 +01:00", "CONNECT", "SYS", "0",
        "(ADDRESS=(PROTOCOL=tcp)(HOST=10.1.1.1)(PORT=40718))", "SYSDBA"), host="dbhost9.example")
    add("oracle:audit:text", "2026-11-26T03:15:00.000+00:00", _txt("Thu Nov 26 04:15:00 2026 +01:00", "CONNECT", "SCOTT", "1017",
        "(ADDRESS=(PROTOCOL=tcp)(HOST=10.9.8.7)(PORT=40800))"), host="dbhost9.example")
    # listener: one established connection, one refused service
    for code, svc in ((0, "PAYDB_TAF.example"), (12514, "NOPE.example")):
        add("oracle:listener:xml", "2026-11-25T23:00:06.406+00:00",
            f"<msg time='2026-11-26T00:00:06.406+01:00' org_id='oracle' comp_id='tnslsnr'\n type='UNKNOWN' level='16' host_id='lsnhost1.example'\n"
            f" host_addr='10.2.2.2' pid='1'>\n <txt>26-NOV-2026 00:00:06 * (CONNECT_DATA=(SERVICE_NAME={svc})(CID=(PROGRAM=sqlplus)(HOST=apphost1.example)(USER=jdoe))) "
            f"* (ADDRESS=(PROTOCOL=tcp)(HOST=10.9.8.7)(PORT=28000)) * establish * {svc} * {code}\n </txt>\n</msg>", host="lsnhost1.example")
    # alert log: a logon block and an outbound failure
    add("oracle:alert:xml", "2026-11-26T12:02:35.000+00:00",
        "2026-11-26T13:02:35.116828+01:00\nHRDB_01_A(15):Session (4022,29340): RECO logon successful: Inbound connection from client\n"
        "HRDB_01_A(15):Session (4022,29340): RECO logon successful: DB Logon User: RECO, Remote Machine: apphost1.example, Program: oracle@apphost1.example (TNS V1-V3), OS User: oracle\n"
        "HRDB_01_A(15):Session (4022,29340): RECO logon successful: Client IP Address: 10.1.1.1\n", host="apphost1.example")
    add("oracle:alert:xml", "2026-11-26T04:00:00.000+00:00",
        "2026-11-26T05:00:00.635954+01:00\n\n***\n\nFatal NI connect error 12514, connecting to:\n"
        " (DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=REMOTE_TAF.example)(CID=(PROGRAM=oracle)(HOST=apphost1.example)(USER=oracle)))"
        "(ADDRESS=(PROTOCOL=tcp)(HOST=10.3.3.3)(PORT=1597))(ADDRESS=(PROTOCOL=tcp)(HOST=10.3.3.4)(PORT=1597)))\n\n  VERSION INFORMATION:\n", host="apphost1.example")
    # Windows and Linux
    add("XmlWinEventLog", "2026-11-26T07:00:00.000+00:00", "Name=Microsoft-Windows-Security-Auditing EventID=4625 Computer=dc1.example "
        "TargetUserName=jdoe TargetDomainName=CORP Status=0xc000006d SubStatus=0xc000006a LogonType=3 IpAddress=10.9.8.7 IpPort=51000 WorkstationName=WS1", host="dc1.example")
    add("XmlWinEventLog", "2026-11-26T07:01:00.000+00:00", "Name=Microsoft-Windows-Security-Auditing EventID=4740 Computer=dc1.example "
        "TargetUserName=jdoe TargetDomainName=CORP", host="dc1.example")
    add("XmlWinEventLog", "2026-11-26T07:00:30.000+00:00", "EventID=4688 Computer=dc1.example SubjectUserName=jdoe NewProcessName='C:\\x\\sqlplus.exe'", host="dc1.example")
    add("linux_secure", "2026-11-26T06:00:00.000+00:00", "Nov 26 07:00:00 apphost1 sshd[1]: Failed password for invalid user admin from 10.9.8.7 port 4242 ssh2", host="apphost1")
    add("linux_secure", "2026-11-26T06:00:05.000+00:00", "Nov 26 07:00:05 apphost1 sshd[1]: Accepted publickey for oracle from 10.1.1.1 port 4243 ssh2", host="apphost1")

    for seed in ("seed-a", "seed-b"):            # every event under two mapped values: counted once
        for st, rows in ev.items():
            d = seeds / seed / "raw" / f"x__{st.replace(':', '_')}"
            d.mkdir(parents=True, exist_ok=True)
            (d / "node.json").write_text(json.dumps({"sourcetype": st}))
            (d / "part-0001.jsonl").write_text("".join(json.dumps({"result": r}) + "\n" for r in rows))
    return ev
