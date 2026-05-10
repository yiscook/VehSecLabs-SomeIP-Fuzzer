def test_import():
    import someip_fuzzer
    assert someip_fuzzer.__version__ == "0.4.0"


def test_main_callable():
    from someip_fuzzer.main import main
    assert callable(main)
