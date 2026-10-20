"""
PySpark ETL layer for the DPI pipeline.

Consumes the Parquet output from Phase 1 (NetworkEvent records),
performs aggregations using Spark DataFrames, and writes summarized
results back to Parquet.

Phase 2: PySpark ETL
- Application summary (packets/blocked/forwarded per app)
- Top talkers (source IPs by packet count)
- Protocol distribution
- Blocked applications list

Uses soft dependency pattern: pyspark is imported inside run(),
so the DPI pipeline and Phase 1 still work if pyspark/Java is missing.
"""


class NetworkEventETL:
    """Applies Spark transformations to NetworkEvent Parquet data."""

    def run(self, input_path: str, output_path: str) -> None:
        """
        Execute the PySpark ETL job.

        Args:
            input_path: Path to Phase 1 Parquet file
                        (output/network_events.parquet).
            output_path: Directory to write summarized Parquet outputs.
                         Four sub-directories created:
                         app_summary, top_talkers, protocol_dist, blocked_apps.
        """
        try:
            from pyspark.sql import SparkSession
            from pyspark.sql import functions as F
        except ImportError:
            # pyspark not installed. Skip ETL silently.
            return

        try:
            spark = (
                SparkSession.builder
                .appName("DPI Network Event ETL")
                .getOrCreate()
            )
        except Exception as exc:
            print(
                f"\nPySpark ETL skipped: {exc}. "
                f"(Need Java to run Spark.)"
            )
            return

        try:
            # ---- Read Phase 1 Parquet output ----
            df = spark.read.parquet(input_path)

            # ---- Transformation 1: Application Summary ----
            # For each application, compute total/blocked/forwarded packets,
            # unique source IP count, and average packet length.
            app_summary = (
                df.groupBy("application")
                .agg(
                    F.count("*").alias("total_packets"),
                    F.sum(
                        F.when(
                            (F.col("decision") == "DROP")
                            & (F.col("blocked") == True),
                            1
                        ).otherwise(0)
                    ).alias("blocked_packets"),
                    F.sum(
                        F.when(F.col("decision") == "FORWARD", 1).otherwise(0)
                    ).alias("forwarded_packets"),
                    F.approx_count_distinct("src_ip").alias("unique_src_ips"),
                    F.avg("packet_length").alias("avg_packet_length"),
                )
            )

            # ---- Transformation 2: Top Talkers ----
            # Top 10 source IPs by total packet count.
            top_talkers = (
                df.groupBy("src_ip")
                .agg(F.count("*").alias("packet_count"))
                .orderBy(F.desc("packet_count"))
                .limit(10)
            )

            # ---- Transformation 3: Protocol Distribution ----
            # Count of packets per protocol (TCP, UDP, ICMP, etc.).
            protocol_dist = (
                df.groupBy("protocol")
                .agg(F.count("*").alias("packet_count"))
            )

            # ---- Transformation 4: Blocked Applications ----
            # Distinct applications that have at least one blocked packet.
            blocked_apps = (
                df.filter(
                    (F.col("decision") == "DROP")
                    & (F.col("blocked") == True)
                )
                .select("application")
                .distinct()
            )

            # ---- Write outputs as Parquet ----
            # Each transformation is written to its own directory under
            # output_path so downstream consumers can pick whichever they
            # need without reading the entire dataset.
            app_summary.write.mode("overwrite").parquet(
                f"{output_path}/app_summary"
            )
            top_talkers.write.mode("overwrite").parquet(
                f"{output_path}/top_talkers"
            )
            protocol_dist.write.mode("overwrite").parquet(
                f"{output_path}/protocol_dist"
            )
            blocked_apps.write.mode("overwrite").parquet(
                f"{output_path}/blocked_apps"
            )

            print(f"\nPySpark ETL completed. Output: {output_path}")
        finally:
            spark.stop()
