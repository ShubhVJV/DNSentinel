from common.fragmentation import (
    fragment_data,
    reassemble_fragments
)


def test_fragmentation():

    data = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
    )

    fragments = fragment_data(
        data,
        fragment_size=10
    )

    print("Original data:")
    print(data)

    print("\nFragments:")

    for i, fragment in enumerate(
        fragments,
        1
    ):
        print(
            f"Fragment {i}: "
            f"{fragment}"
        )

    assert len(fragments) == 7

    for fragment in fragments:
        assert len(fragment) <= 10

    reconstructed = reassemble_fragments(
        [
            {
                "sequence": i + 1,
                "data": fragment
            }
            for i, fragment in enumerate(fragments)
        ]
    )

    print("\nReassembled data:")
    print(reconstructed)

    assert reconstructed == data

    print(
        "\nFragmentation and "
        "reassembly test passed!"
    )


def test_out_of_order_fragments():

    fragments = [
        {
            "sequence": 3,
            "data": "CCC"
        },
        {
            "sequence": 1,
            "data": "AAA"
        },
        {
            "sequence": 4,
            "data": "DDD"
        },
        {
            "sequence": 2,
            "data": "BBB"
        }
    ]

    reconstructed = reassemble_fragments(
        fragments
    )

    assert reconstructed == "AAABBBCCCDDD"

    print(
        "Out-of-order reassembly test passed!"
    )


if __name__ == "__main__":

    test_fragmentation()

    test_out_of_order_fragments()

    print(
        "\nAll fragmentation tests passed!"
    )