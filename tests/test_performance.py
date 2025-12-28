#!/usr/bin/env python3

"""
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-25 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Performance tests for BRS-KB
Benchmarks for reverse mapping, search, and context loading
"""

import time

from brs_kb import (
    get_all_contexts,
    get_payloads_by_context,
    get_vulnerability_details,
    list_contexts,
    search_payloads,
)
from brs_kb.payload_index import get_index, rebuild_index
from brs_kb.reverse_map import find_contexts_for_payload, predict_contexts_ml_ready


class TestContextLoadingPerformance:
    """Test context loading performance"""

    def test_list_contexts_performance(self):
        """Test list_contexts performance"""
        start_time = time.time()
        contexts = list_contexts()
        elapsed = time.time() - start_time

        assert len(contexts) > 0
        assert elapsed < 1.0, f"list_contexts took {elapsed:.3f}s, expected < 1.0s"
        print(f"✓ list_contexts: {elapsed:.3f}s for {len(contexts)} contexts")

    def test_get_all_contexts_performance(self):
        """Test get_all_contexts performance"""
        start_time = time.time()
        all_contexts = get_all_contexts()
        elapsed = time.time() - start_time

        assert len(all_contexts) > 0
        assert elapsed < 2.0, f"get_all_contexts took {elapsed:.3f}s, expected < 2.0s"
        print(f"✓ get_all_contexts: {elapsed:.3f}s for {len(all_contexts)} contexts")

    def test_get_vulnerability_details_performance(self):
        """Test get_vulnerability_details performance"""
        contexts = list_contexts()
        test_contexts = contexts[:10]  # Test first 10

        start_time = time.time()
        for context in test_contexts:
            details = get_vulnerability_details(context)
            assert details is not None
        elapsed = time.time() - start_time

        avg_time = elapsed / len(test_contexts)
        assert (
            avg_time < 0.1
        ), f"Average get_vulnerability_details took {avg_time:.3f}s, expected < 0.1s"
        print(
            f"✓ get_vulnerability_details: {avg_time:.3f}s average for {len(test_contexts)} contexts"
        )


class TestReverseMappingPerformance:
    """Test reverse mapping performance"""

    def test_find_contexts_for_payload_single(self):
        """Test single payload analysis performance"""
        payload = "<script>alert(1)</script>"

        start_time = time.time()
        result = find_contexts_for_payload(payload)
        elapsed = time.time() - start_time

        assert result is not None
        assert elapsed < 0.5, f"find_contexts_for_payload took {elapsed:.3f}s, expected < 0.5s"
        print(f"✓ find_contexts_for_payload (single): {elapsed:.3f}s")

    def test_find_contexts_for_payload_batch(self):
        """Test batch payload analysis performance"""
        test_payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img onerror=alert(1)>",
            "{{constructor.constructor('alert(1)')()}}",
            "<svg onload=alert(1)>",
        ]

        start_time = time.time()
        for payload in test_payloads:
            result = find_contexts_for_payload(payload)
            assert result is not None
        elapsed = time.time() - start_time

        avg_time = elapsed / len(test_payloads)
        assert (
            avg_time < 0.3
        ), f"Average find_contexts_for_payload took {avg_time:.3f}s, expected < 0.3s"
        print(
            f"✓ find_contexts_for_payload (batch): {avg_time:.3f}s average for {len(test_payloads)} payloads"
        )

    def test_find_contexts_for_payload_caching(self):
        """Test that caching improves performance"""
        payload = "<script>alert(document.cookie)</script>"

        # First call (cold cache)
        start_time = time.time()
        result1 = find_contexts_for_payload(payload)
        first_call_time = time.time() - start_time

        # Second call (warm cache)
        start_time = time.time()
        result2 = find_contexts_for_payload(payload)
        second_call_time = time.time() - start_time

        assert result1 == result2
        # Cached call should be faster (or at least not slower)
        assert (
            second_call_time <= first_call_time * 1.5
        ), f"Caching didn't help: {first_call_time:.3f}s -> {second_call_time:.3f}s"
        print(f"✓ Caching performance: {first_call_time:.3f}s -> {second_call_time:.3f}s")

    def test_predict_contexts_ml_ready_performance(self):
        """Test ML-ready feature extraction performance"""
        payload = "<script>alert(document.cookie)</script>"

        start_time = time.time()
        result = predict_contexts_ml_ready(payload)
        elapsed = time.time() - start_time

        assert result is not None
        assert "features" in result
        assert elapsed < 0.5, f"predict_contexts_ml_ready took {elapsed:.3f}s, expected < 0.5s"
        print(f"✓ predict_contexts_ml_ready: {elapsed:.3f}s")


class TestPayloadSearchPerformance:
    """Test payload search performance"""

    def test_search_payloads_basic(self):
        """Test basic payload search performance"""
        start_time = time.time()
        results = search_payloads("script")
        elapsed = time.time() - start_time

        assert isinstance(results, list)
        assert elapsed < 1.0, f"search_payloads took {elapsed:.3f}s, expected < 1.0s"
        print(f"✓ search_payloads (basic): {elapsed:.3f}s for {len(results)} results")

    def test_search_payloads_with_different_queries(self):
        """Test search with different queries"""
        queries = ["script", "alert", "xss", "html"]

        for query in queries:
            start_time = time.time()
            results = search_payloads(query)
            elapsed = time.time() - start_time

            assert elapsed < 1.0, f"search_payloads('{query}') took {elapsed:.3f}s, expected < 1.0s"
            print(f"✓ search_payloads('{query}'): {elapsed:.3f}s for {len(results)} results")

    def test_search_payloads_index_performance(self):
        """Test that indexing improves search performance"""
        # Rebuild index to ensure it's fresh
        rebuild_index()
        index = get_index()

        # Test indexed search
        start_time = time.time()
        results = index.search("script", limit=10)
        elapsed = time.time() - start_time

        assert len(results) >= 0
        assert elapsed < 0.5, f"Indexed search took {elapsed:.3f}s, expected < 0.5s"
        print(f"✓ Indexed search: {elapsed:.3f}s for {len(results)} results")

    def test_get_payloads_by_context_performance(self):
        """Test get_payloads_by_context performance"""
        contexts = list_contexts()
        test_contexts = contexts[:5]  # Test first 5

        for context in test_contexts:
            start_time = time.time()
            payloads = get_payloads_by_context(context)
            elapsed = time.time() - start_time

            assert isinstance(payloads, list)
            assert (
                elapsed < 0.5
            ), f"get_payloads_by_context('{context}') took {elapsed:.3f}s, expected < 0.5s"
            print(
                f"✓ get_payloads_by_context('{context}'): {elapsed:.3f}s for {len(payloads)} payloads"
            )


class TestIndexPerformance:
    """Test payload index performance"""

    def test_index_build_performance(self):
        """Test index building performance"""
        from brs_kb.payload_index import PayloadIndex

        index = PayloadIndex()
        start_time = time.time()
        index.build_indexes()
        elapsed = time.time() - start_time

        assert index._initialized
        assert elapsed < 2.0, f"Index build took {elapsed:.3f}s, expected < 2.0s"
        print(f"✓ Index build: {elapsed:.3f}s")

    def test_index_rebuild_performance(self):
        """Test index rebuild performance"""
        index = get_index()

        start_time = time.time()
        index.rebuild_indexes()
        elapsed = time.time() - start_time

        assert elapsed < 2.0, f"Index rebuild took {elapsed:.3f}s, expected < 2.0s"
        print(f"✓ Index rebuild: {elapsed:.3f}s")

    def test_index_search_performance(self):
        """Test index search performance"""
        index = get_index()
        queries = ["script", "alert", "xss"]

        for query in queries:
            start_time = time.time()
            index.search(query, limit=10)
            elapsed = time.time() - start_time

            assert elapsed < 0.3, f"Index search('{query}') took {elapsed:.3f}s, expected < 0.3s"
            print(f"✓ Index search('{query}'): {elapsed:.3f}s")


class TestMemoryUsage:
    """Test memory usage"""

    def test_context_loading_memory(self):
        """Test memory usage for context loading"""
        import sys

        # Get initial memory
        initial_size = sys.getsizeof(list_contexts())

        # Load all contexts
        all_contexts = get_all_contexts()
        final_size = sys.getsizeof(all_contexts)

        # Memory should be reasonable
        memory_per_context = (final_size - initial_size) / len(all_contexts) if all_contexts else 0
        assert (
            memory_per_context < 10000
        ), f"Memory per context: {memory_per_context} bytes, expected < 10KB"
        print(f"✓ Memory per context: {memory_per_context:.0f} bytes")

    def test_index_memory(self):
        """Test index memory usage"""
        import sys

        from brs_kb.payload_index import PayloadIndex

        index = PayloadIndex()
        index.build_indexes()

        index_size = sys.getsizeof(index)
        stats = index.get_index_stats()

        # Memory should be reasonable
        memory_per_payload = (
            index_size / stats["total_payloads"] if stats["total_payloads"] > 0 else 0
        )
        assert (
            memory_per_payload < 1000
        ), f"Memory per payload: {memory_per_payload} bytes, expected < 1KB"
        print(f"✓ Index memory per payload: {memory_per_payload:.0f} bytes")


class TestConcurrentPerformance:
    """Test concurrent operations performance"""

    def test_concurrent_payload_analysis(self):
        """Test concurrent payload analysis"""
        import concurrent.futures

        payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img onerror=alert(1)>",
        ] * 10  # 30 total

        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(find_contexts_for_payload, payload) for payload in payloads]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

        elapsed = time.time() - start_time

        assert len(results) == len(payloads)
        assert elapsed < 5.0, f"Concurrent analysis took {elapsed:.3f}s, expected < 5.0s"
        print(f"✓ Concurrent analysis: {elapsed:.3f}s for {len(payloads)} payloads")

    def test_concurrent_search(self):
        """Test concurrent search operations"""
        import concurrent.futures

        queries = ["script", "alert", "xss", "html", "javascript"] * 5  # 25 total

        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(search_payloads, query) for query in queries]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

        elapsed = time.time() - start_time

        assert len(results) == len(queries)
        assert elapsed < 5.0, f"Concurrent search took {elapsed:.3f}s, expected < 5.0s"
        print(f"✓ Concurrent search: {elapsed:.3f}s for {len(queries)} queries")


class TestScalability:
    """Test scalability with large datasets"""

    def test_large_payload_analysis(self):
        """Test performance with many payload analyses"""
        payloads = [f"<script>alert({i})</script>" for i in range(100)]

        start_time = time.time()
        for payload in payloads:
            result = find_contexts_for_payload(payload)
            assert result is not None
        elapsed = time.time() - start_time

        avg_time = elapsed / len(payloads)
        assert avg_time < 0.1, f"Average time per payload: {avg_time:.3f}s, expected < 0.1s"
        print(
            f"✓ Large batch analysis: {elapsed:.3f}s for {len(payloads)} payloads ({avg_time:.3f}s avg)"
        )

    def test_large_search_queries(self):
        """Test performance with many search queries"""
        queries = [f"test{i}" for i in range(50)]

        start_time = time.time()
        for query in queries:
            results = search_payloads(query)
            assert isinstance(results, list)
        elapsed = time.time() - start_time

        avg_time = elapsed / len(queries)
        assert avg_time < 0.2, f"Average time per query: {avg_time:.3f}s, expected < 0.2s"
        print(
            f"✓ Large batch search: {elapsed:.3f}s for {len(queries)} queries ({avg_time:.3f}s avg)"
        )


# Benchmark tests (require pytest-benchmark plugin)
# To run: pytest tests/test_performance.py -k benchmark --benchmark-only
# class TestBenchmarks:
#     """Benchmark tests (can be run separately with pytest-benchmark)"""
#
#     def test_benchmark_reverse_mapping(self, benchmark):
#         """Benchmark reverse mapping"""
#         payload = "<script>alert(document.cookie)</script>"
#         result = benchmark(find_contexts_for_payload, payload)
#         assert result is not None
#
#     def test_benchmark_search(self, benchmark):
#         """Benchmark payload search"""
#         result = benchmark(search_payloads, "script")
#         assert isinstance(result, list)
#
#     def test_benchmark_context_loading(self, benchmark):
#         """Benchmark context loading"""
#         result = benchmark(list_contexts)
#         assert len(result) > 0
