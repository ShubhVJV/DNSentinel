class CongestionController:

    def __init__(
        self,
        initial_delay=0.05,
        min_delay=0.01,
        max_delay=1.0
    ):
        self.delay = initial_delay
        self.min_delay = min_delay
        self.max_delay = max_delay

        self.rtt_history = []
        self.loss_count = 0
        self.total_packets = 0

    def record_rtt(self, rtt):
        self.rtt_history.append(rtt)

        if len(self.rtt_history) > 20:
            self.rtt_history.pop(0)

    def record_success(self):
        self.total_packets += 1

    def record_loss(self):
        self.total_packets += 1
        self.loss_count += 1

    def average_rtt(self):
        if not self.rtt_history:
            return 0.0

        return sum(self.rtt_history) / len(self.rtt_history)

    def loss_rate(self):
        if self.total_packets == 0:
            return 0.0

        return self.loss_count / self.total_packets

    def update(self):

        avg_rtt = self.average_rtt()
        loss_rate = self.loss_rate()

        if loss_rate > 0.10:

            self.delay = min(
                self.delay * 1.5,
                self.max_delay
            )

        elif avg_rtt > 100:

            self.delay = min(
                self.delay * 1.25,
                self.max_delay
            )

        elif avg_rtt < 20 and loss_rate == 0:

            self.delay = max(
                self.delay * 0.9,
                self.min_delay
            )

    def get_delay(self):
        return self.delay