"""Static work-sharding for multi-process scanning must be exhaustive,
disjoint, and require zero coordination between worker processes."""

from __future__ import annotations

from app.core.process_worker import iter_sharded_targets
from app.storage.models import ScanConfig


def test_shards_partition_inline_targets_without_overlap(tmp_path):
    targets = [f"host{i}.example" for i in range(97)]  # prime count, no even split
    config = ScanConfig(targets=targets, output_dir=str(tmp_path))
    num_workers = 5

    shards = [
        {url for _idx, url in iter_sharded_targets(config, worker_id, num_workers)}
        for worker_id in range(num_workers)
    ]

    union: set[str] = set()
    for shard in shards:
        union |= shard
    expected = {f"https://{t}" for t in targets}  # normalize_target adds a scheme
    assert union == expected

    for i in range(num_workers):
        for j in range(i + 1, num_workers):
            assert not (shards[i] & shards[j]), f"worker {i} and {j} both got the same target"


def test_shards_partition_streamed_file(tmp_path):
    targets_path = tmp_path / "targets.txt"
    lines = [f"http://target-{i}.example" for i in range(233)]
    targets_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    config = ScanConfig(targets=[], targets_path=str(targets_path), output_dir=str(tmp_path))
    num_workers = 4

    shards = [list(iter_sharded_targets(config, worker_id, num_workers)) for worker_id in range(num_workers)]
    total = sum(len(shard) for shard in shards)
    assert total == len(lines)

    combined: set[str] = set()
    for shard in shards:
        combined.update(url for _idx, url in shard)
    assert combined == {f"http://target-{i}.example" for i in range(233)}


def test_single_worker_shard_covers_everything(tmp_path):
    config = ScanConfig(targets=["a.example", "b.example"], output_dir=str(tmp_path))
    shard = list(iter_sharded_targets(config, worker_id=0, num_workers=1))
    assert shard == [(0, "https://a.example"), (1, "https://b.example")]


def test_sharded_skip_indices_for_resume(tmp_path):
    config = ScanConfig(targets=["a.example", "b.example", "c.example", "d.example"], output_dir=str(tmp_path))
    skip = {0, 2}
    shard = list(iter_sharded_targets(config, 0, 1, skip_indices=skip))
    assert shard == [(1, "https://b.example"), (3, "https://d.example")]
