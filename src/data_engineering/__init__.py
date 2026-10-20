"""
Data Engineering layer for the DPI Engine.

Phase 1: Parquet (structured network events → columnar storage).
Phase 2: PySpark ETL (aggregations and summary datasets).
Phase 3: PostgreSQL (batch persistence for structured events).
Phase 4: Kafka (JSON event streaming).
Phase 5: Airflow (pipeline orchestration).

This layer reads from the existing DPI pipeline.
It does not modify any DPI code.
"""
