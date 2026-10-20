"""
Phase 5: Airflow DAG for the DPI Data Engineering pipeline.
"""

import json
from datetime import datetime

try:
    from airflow import DAG
    from airflow.operators.bash import BashOperator
    from airflow.operators.python import PythonOperator
    from airflow.providers.postgres.hooks.postgres import PostgresHook
    from airflow.providers.apache.kafka.operators.produce import ProduceToTopicOperator
    _AIRFLOW_AVAILABLE = True
except ImportError:
    _AIRFLOW_AVAILABLE = False


def load_parquet_to_postgres(**kwargs):
    """Load real Parquet events into PostgreSQL."""
    import pyarrow.parquet as pq

    table = pq.read_table("/workspace/output/network_events.parquet")
    rows = table.to_pylist()

    if not rows:
        raise RuntimeError("No events found in network_events.parquet")

    hook = PostgresHook(postgres_conn_id="dpi_postgres")
    conn = hook.get_conn()

    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS network_events (
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    packet_length INTEGER,
                    sni TEXT,
                    http_host TEXT,
                    http_method TEXT,
                    http_path TEXT,
                    user_agent TEXT,
                    application TEXT,
                    decision TEXT,
                    blocked BOOLEAN,
                    flow_packet_count INTEGER
                )
            """)

            insert_sql = """
                INSERT INTO network_events (
                    src_ip, dst_ip, src_port, dst_port, protocol,
                    packet_length, sni, http_host, http_method,
                    http_path, user_agent, application, decision,
                    blocked, flow_packet_count
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s)
            """

            values = [
                (
                    row["src_ip"],
                    row["dst_ip"],
                    row["src_port"],
                    row["dst_port"],
                    row["protocol"],
                    row["packet_length"],
                    row["sni"],
                    row["http_host"],
                    row["http_method"],
                    row["http_path"],
                    row["user_agent"],
                    row["application"],
                    row["decision"],
                    row["blocked"],
                    row["flow_packet_count"],
                )
                for row in rows
            ]

            cur.executemany(insert_sql, values)

        conn.commit()
        print(f"PostgreSQL: {len(rows)} rows loaded from Parquet.")
    finally:
        conn.close()


def produce_network_events(**kwargs):
    """Publish every real Parquet event to Kafka."""
    import pyarrow.parquet as pq

    table = pq.read_table("/workspace/output/network_events.parquet")

    for row in table.to_pylist():
        key = f"{row['src_ip']}->{row['dst_ip']}"
        value = json.dumps(row, default=str)
        yield key, value


def publish_network_events(**kwargs):
    import json
    import pyarrow.parquet as pq
    from confluent_kafka import Producer

    table = pq.read_table('/workspace/output/network_events.parquet')
    rows = table.to_pylist()
    if not rows:
        raise RuntimeError('No events found in network_events.parquet')

    producer = Producer({'bootstrap.servers': 'kafka:29092'})
    for row in rows:
        producer.produce(
            'network_events',
            key=f"{row['src_ip']}->{row['dst_ip']}",
            value=json.dumps(row, default=str),
        )
        producer.poll(0)
    producer.flush()
    print(f'Kafka: {len(rows)} real events published.')


def _build_dag():
    if not _AIRFLOW_AVAILABLE:
        return None

    with DAG(
        dag_id="dpi_data_engineering_pipeline",
        schedule="@daily",
        start_date=datetime(2026, 9, 13),
        catchup=False,
        tags=["dpi", "data-engineering"],
    ) as dag:

        run_dpi = BashOperator(
            task_id="run_dpi",
            bash_command="cd /workspace && python main.py",
            env={
                "DPI_SKIP_EXTERNAL_SINKS": "1",
            },
        )

        run_pyspark = BashOperator(
            task_id="run_pyspark_etl",
            bash_command=(
                "cd /workspace && python -c "
                "'from src.data_engineering.pyspark_etl import NetworkEventETL; "
                "NetworkEventETL().run("
                "\"output/network_events.parquet\", "
                "\"output/pyspark_etl_output\")'"
            ),
        )

        load_postgres = PythonOperator(
            task_id="load_postgres",
            python_callable=load_parquet_to_postgres,
        )

        publish_kafka = PythonOperator(
            task_id='publish_kafka',
            python_callable=publish_network_events,
        )

        run_dpi >> run_pyspark >> load_postgres >> publish_kafka

    return dag


DAG = _build_dag()





