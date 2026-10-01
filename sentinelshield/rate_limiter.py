from collections import defaultdict, deque
from time import monotonic

class RateLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self.hits = defaultdict(deque)

    def check(self, key: str) -> tuple[bool, int]:
        now = monotonic()
        q = self.hits[key]
        while q and (now - q[0]) > self.window:
            q.popleft()
        q.append(now)
        return len(q) > self.limit, len(q)
