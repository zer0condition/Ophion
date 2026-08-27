"""Deterministic host models for kernel lifecycle contracts.

These models contain no target integration. They make interval and attachment
state rules executable in CI before the corresponding kernel paths run.
"""


class ConcealRanges:
    MAX_U64 = (1 << 64) - 1

    def __init__(self, page_size=0x1000, maximum_ranges=8192):
        self.page_size = page_size
        self.maximum_ranges = maximum_ranges
        self._ranges = []
        self._published = False
        self._generation = 0

    def snapshot(self):
        return [(start, end - start) for start, end in self._ranges]

    def _normalized(self, address, size):
        if address <= 0 or size <= 0 or address > self.MAX_U64:
            return None
        if size > self.MAX_U64 - address:
            return None
        last = address + size
        if last > self.MAX_U64 - (self.page_size - 1):
            return None
        start = address & ~(self.page_size - 1)
        end = (last + self.page_size - 1) & ~(self.page_size - 1)
        return (start, end) if end > start else None

    def add_physical(self, address, size):
        interval = self._normalized(address, size)
        if self._published or interval is None:
            return False
        start, end = interval
        merged = []
        inserted = False
        for current_start, current_end in self._ranges:
            if current_end < start:
                merged.append((current_start, current_end))
            elif end < current_start:
                if not inserted:
                    merged.append((start, end))
                    inserted = True
                merged.append((current_start, current_end))
            else:
                start = min(start, current_start)
                end = max(end, current_end)
        if not inserted:
            merged.append((start, end))
        if len(merged) > self.maximum_ranges:
            return False
        self._ranges = merged
        self._generation += 1
        return True

    def add_virtual(self, address, size, translate):
        interval = self._normalized(address, size)
        if self._published or interval is None:
            return False
        start, end = interval
        physical = []
        page = start
        while page < end:
            translated = translate(page)
            if not translated:
                return False
            physical.append(translated & ~(self.page_size - 1))
            page += self.page_size
        before = (list(self._ranges), self._generation)
        for translated in physical:
            if not self.add_physical(translated, self.page_size):
                self._ranges, self._generation = before
                return False
        return True

    def publish(self):
        if self._published or not self._ranges:
            return (0, [])
        self._published = True
        return (self._generation, self.snapshot())

    def contains(self, address):
        low, high = 0, len(self._ranges)
        while low < high:
            middle = low + (high - low) // 2
            start, end = self._ranges[middle]
            if address < start:
                high = middle
            elif address >= end:
                low = middle + 1
            else:
                return True
        return False


class AttachmentManager:
    def _failure(self, failure):
        return {"state": "failed", "failure": failure, "ownership": 0}

    def execute(self, request, available):
        known = {"size", "version", "header_bytes", "mode", "flags",
                 "required", "optional", "nonce", "reserved"}
        if (set(request) != known or request["size"] != 48 or
                request["version"] != 1 or request["header_bytes"] != 48 or
                request["reserved"] != 0 or request["flags"] & ~0xF or
                request["mode"] not in ("probe", "root", "nested") or
                request["nonce"] == (0, 0)):
            return self._failure("abi-mismatch")
        if request["required"] & ~available:
            return self._failure("feature-missing")
        negotiated = request["required"] | (request["optional"] & available)
        if request["mode"] == "probe":
            return {"state": "eligible", "failure": "none",
                    "ownership": 0, "features": negotiated}
        return self._failure("provider-unavailable")

    def rollback(self, ownership, release):
        for bit in range(63, -1, -1):
            mask = 1 << bit
            if ownership & mask:
                release(bit)
                ownership &= ~mask
        return ownership