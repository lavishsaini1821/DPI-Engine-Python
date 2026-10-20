"""
Phase 3: PostgreSQL sink for NetworkEvent records.

Writes structured events to a `network_events` table in PostgreSQL.
This completes the Parquet -> PySpark -> PostgreSQL -> Kafka pipeline.

Soft dependency: psycopg2 is imported inside run(), so the DPI
pipeline still works if PostgreSQL is not configured.
"""

INSERT_SQL = """
INSERT INTO network_events (
    src_ip, dst_ip, src_port, dst_port, protocol, packet_length,
    sni, http_host, http_method, http_path, user_agent,
    application, decision, blocked, flow_packet_count
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


class PostgresSink:
    """Persists NetworkEvent lists to PostgreSQL."""

    def write(self, events, connection_string: str,
              table: str = "network_events") -> None:
        """
        Batch-insert events into PostgreSQL.

        Args:
            events: List of NetworkEvent dataclasses.
            connection_string: psycopg2 connection URI, e.g.
                "dbname=dpi user=postgres password=secret".
        """
        try:
            import psycopg2
        except ImportError:
            print("\nPostgresSink skipped — psycopg2 not installed.")
            return False

        if not events:
            print("\nPostgresSink: no events to write.")
            return False

        try:
            conn = psycopg2.connect(connection_string)
        except Exception as exc:
            print(f"\nPostgresSink skipped: {exc}. (Need PostgreSQL server running.)")
            return False

        try:
            with conn.cursor() as cur:
                cur.execute(
                    f"CREATE TABLE IF NOT EXISTS {table} ("
                    "src_ip TEXT, dst_ip TEXT, src_port INTEGER,"
                    " dst_port INTEGER, protocol TEXT,"
                    " packet_length INTEGER, sni TEXT, http_host TEXT,"
                    " http_method TEXT, http_path TEXT, user_agent TEXT,"
                    " application TEXT, decision TEXT, blocked BOOLEAN,"
                    " flow_packet_count INTEGER)"
                )
                rows = [
                    (
                        e.src_ip, e.dst_ip, e.src_port, e.dst_port,
                        e.protocol, e.packet_length, e.sni, e.http_host,
                        e.http_method, e.http_path, e.user_agent,
                        e.application, e.decision, e.blocked,
                        e.flow_packet_count,
                    )
                    for e in events
                ]
                cur.executemany(INSERT_SQL.replace("network_events", table), rows)
            conn.commit()
            print(f"\nPostgresSink: {len(events)} rows written to '{table}'.")
            return True
        finally:
            conn.close()
