class HTTPHostExtractor:
    """
    Extracts the Host header from HTTP requests.
    """
    def extract(self, payload):

        if not payload:
            return None

        try:
            text = payload.decode("utf-8",errors="ignore")
        except Exception:
            return None

        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                host = line[5:].strip()

                if host:
                    return host
        return None