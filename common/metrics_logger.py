import csv
import os
from datetime import datetime


METRICS_FILE = "analysis/metrics.csv"


def initialize_metrics_file():

    os.makedirs(
        "analysis",
        exist_ok=True
    )

    if not os.path.exists(METRICS_FILE):

        with open(
            METRICS_FILE,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "timestamp",
                "client_id",
                "session_id",
                "fragment",
                "total_fragments",
                "rtt_ms",
                "success",
                "loss",
                "adaptive_delay"
            ])


def log_metric(
    client_id,
    session_id,
    fragment,
    total_fragments,
    rtt_ms,
    success,
    loss,
    adaptive_delay
):

    initialize_metrics_file()

    with open(
        METRICS_FILE,
        "a",
        newline=""
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            datetime.now().isoformat(),
            client_id,
            session_id,
            fragment,
            total_fragments,
            rtt_ms,
            success,
            loss,
            adaptive_delay
        ])