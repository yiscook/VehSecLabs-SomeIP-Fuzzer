def test_import():
    import someip_fuzzer
    assert someip_fuzzer.__version__ == "0.2.0"


def test_main_callable():
    from someip_fuzzer.main import main
    assert callable(main)
