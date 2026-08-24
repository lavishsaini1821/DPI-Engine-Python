from src.v2.pipeline import V2Pipeline

def test_v2_pipeline_processes_pcap():
    pipeline = V2Pipeline("input/test_dpi.pcap",worker_count=4,)

    stats, results, application_stats = pipeline.run()

    report = pipeline.get_report()

    print("\nV2 DPI REPORT")
    print("=" * 35)

    print(f"Total Processed : {report['total_packets']}")
    print(f"Forwarded       : {report['forwarded']}")
    print(f"Dropped         : {report['dropped']}")

    print("\nApplication Statistics")
    print("-" * 35)

    for app, count in report["applications"].items():
        print(f"{app:<15}: {count}")

    print("\nWorker Statistics")
    print("-" * 35)

    for worker_id, count in report["workers"].items():
        print(f"Worker {worker_id:<8}: {count} packets")
        
    total_processed = len(results)
    print("Worker Statistics:")

    forwarded = sum(
        1
        for result in results
        if result["decision"] == "FORWARD"
    )

    dropped = sum(
        1
        for result in results
        if result["decision"] == "DROP"
    )

    assert total_processed == 77
    assert forwarded + dropped == 77

if __name__ == "__main__":
    test_v2_pipeline_processes_pcap()
    print("V2 Real PCAP Pipeline Test: PASS")
