import os

import pandas as pd
import matplotlib.pyplot as plt


METRICS_FILE = "analysis/metrics.csv"
GRAPH_DIR = "graphs"


def main():

    os.makedirs(
        GRAPH_DIR,
        exist_ok=True
    )

    df = pd.read_csv(
        METRICS_FILE
    )

    df["rtt_ms"] = pd.to_numeric(
        df["rtt_ms"],
        errors="coerce"
    )

    successful = df[
        df["success"] == 1
    ]

    plt.figure()

    plt.plot(
        successful["fragment"],
        successful["rtt_ms"],
        marker="o"
    )

    plt.xlabel("Fragment")
    plt.ylabel("RTT (ms)")
    plt.title("RTT vs Fragment")
    plt.grid(True)

    plt.savefig(
        os.path.join(
            GRAPH_DIR,
            "rtt_vs_fragment.png"
        ),
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    plt.figure()

    plt.plot(
        df["fragment"],
        df["adaptive_delay"],
        marker="o"
    )

    plt.xlabel("Fragment")
    plt.ylabel("Adaptive Delay (seconds)")
    plt.title(
        "Adaptive Delay vs Fragment"
    )
    plt.grid(True)

    plt.savefig(
        os.path.join(
            GRAPH_DIR,
            "adaptive_delay_vs_fragment.png"
        ),
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    loss_count = df["loss"].sum()
    success_count = df["success"].sum()

    plt.figure()

    plt.bar(
        ["Successful", "Lost"],
        [success_count, loss_count]
    )

    plt.ylabel("Packets")
    plt.title("Packet Success vs Loss")
    plt.grid(axis="y")

    plt.savefig(
        os.path.join(
            GRAPH_DIR,
            "packet_loss.png"
        ),
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print("Graphs generated successfully.")


if __name__ == "__main__":
    main()