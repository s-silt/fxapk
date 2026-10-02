from io import BytesIO

import pytest

from apkscan.core.bounded_io import read_limited


@pytest.mark.parametrize("size,limit", [(0, 0), (1, 0), (3, 3), (4, 3), (100000, 100000), (100001, 100000)])
def test_incremental_read_has_exact_old_limit_semantics(size, limit):
    raw = b"x" * size
    assert read_limited(BytesIO(raw), limit) == raw[:limit + 1]


def test_small_file_never_requests_the_whole_large_budget():
    reads = []
    class Stream(BytesIO):
        def read(self, size=-1):
            reads.append(size)
            return super().read(size)
    assert read_limited(Stream(b'{"synthetic":true}'), 128 * 1024 * 1024) == b'{"synthetic":true}'
    assert max(reads) <= 65536
