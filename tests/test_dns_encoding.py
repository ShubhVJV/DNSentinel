from common.dns_encoding import split_dns_labels, join_dns_labels


def test_dns_label_splitting():

    data = (
        "gf6egmbrprjuku2tjfhu4mbqgf6dc7ceifkec7br"
        "g56eqzlmnrxsarcoknsw45djnzswyii"
    )

    labels = split_dns_labels(data)

    print("DNS labels:")
    for i, label in enumerate(labels, 1):
        print(f"Label {i}: {label}")
        print(f"Length: {len(label)}")

    # Every label must be <= 63 characters
    for label in labels:
        assert len(label) <= 63

    # Reconstruct original data
    reconstructed = join_dns_labels(labels)

    assert reconstructed == data

    print("\nDNS label splitting test passed!")


if __name__ == "__main__":
    test_dns_label_splitting()