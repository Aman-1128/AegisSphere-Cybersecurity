import pandas as pd


def analyze_logs(df):
    """
    Analyze uploaded security logs and extract
    useful network-level information.
    """

    # Normalize column names
    df.columns = df.columns.str.strip()

    total_logs = len(df)

    # -------------------------------
    # Source IP Analysis
    # -------------------------------

    source_ip_column = next(
        (
            col for col in df.columns
            if col.lower() in [
                "source ip",
                "src ip",
                "source_ip",
                "src_ip"
            ]
        ),
        None
    )

    if source_ip_column:
        unique_source_ips = int(
            df[source_ip_column].nunique()
        )

        repeated_source_ips = (
            df[source_ip_column]
            .value_counts()
            .loc[lambda x: x > 1]
            .head(10)
            .to_dict()
        )
    else:
        unique_source_ips = 0
        repeated_source_ips = {}

    # -------------------------------
    # Protocol Analysis
    # -------------------------------

    protocol_column = next(
        (
            col for col in df.columns
            if col.lower() == "protocol"
        ),
        None
    )

    if protocol_column:
        protocol_distribution = (
            df[protocol_column]
            .value_counts()
            .to_dict()
        )
    else:
        protocol_distribution = {}

    # -------------------------------
    # Destination Port Analysis
    # -------------------------------

    port_column = next(
        (
            col for col in df.columns
            if col.lower() in [
                "destination port",
                "dest port",
                "dst port",
                "destination_port"
            ]
        ),
        None
    )

    if port_column:
        top_destination_ports = (
            df[port_column]
            .value_counts()
            .head(10)
            .to_dict()
        )
    else:
        top_destination_ports = {}

    # -------------------------------
    # Return Analysis
    # -------------------------------

    return {
        "total_logs": total_logs,
        "unique_source_ips": unique_source_ips,
        "repeated_source_ips": repeated_source_ips,
        "protocol_distribution": protocol_distribution,
        "top_destination_ports": top_destination_ports
    }