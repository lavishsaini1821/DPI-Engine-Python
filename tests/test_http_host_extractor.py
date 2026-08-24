from src.http_host_extractor import HTTPHostExtractor

def test_http_host_is_extracted():
    extractor = HTTPHostExtractor()
    payload = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Test\r\n"
        b"\r\n"
    )
    result = extractor.extract(payload)
    assert result == "example.com"

def test_host_header_is_case_insensitive():
    extractor = HTTPHostExtractor()
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"HOST: google.com\r\n"
        b"\r\n"
    )
    result = extractor.extract(payload)
    assert result == "google.com"


def test_missing_host_returns_none():
    extractor = HTTPHostExtractor()
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"User-Agent: Test\r\n"
        b"\r\n"
    )

    result = extractor.extract(payload)
    assert result is None

if __name__ == "__main__":

    test_http_host_is_extracted()
    test_host_header_is_case_insensitive()
    test_missing_host_returns_none()

    print("HTTP Host Extractor Test: PASS")