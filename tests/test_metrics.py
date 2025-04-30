import time

from netarmageddon.utils.metrics import AttackMetrics


def test_metrics_tracking() -> None:
    metrics = AttackMetrics()
    metrics.start_timer()
    time.sleep(0.1)
    metrics.increment_packets()
    metrics.increment_packets()
    metrics.increment_errors()
    stats = metrics.get_stats()

    assert stats["packets_per_sec"] > 10
    assert stats["error_rate"] == 0.5
