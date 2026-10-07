import time


def get_timestamp():
    return time.perf_counter()


def calculate_rtt(start_time, end_time):
    return (end_time - start_time) * 1000


def calculate_average(values):
    if not values:
        return 0.0

    return sum(values) / len(values)


def calculate_min(values):
    if not values:
        return 0.0

    return min(values)


def calculate_max(values):
    if not values:
        return 0.0

    return max(values)