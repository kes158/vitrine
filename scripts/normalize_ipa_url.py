"""Turn a Dropbox share URL into a direct-download URL without logging it."""

import os
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def normalize(url):
    # Some copied Markdown links contain an escaped ampersand.
    url = url.strip().replace(r"\&", "&")
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in {"dropbox.com", "www.dropbox.com"}:
        return url

    query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True)
             if key != "dl"]
    query.append(("dl", "1"))
    return urlunsplit(parts._replace(query=urlencode(query)))


if __name__ == "__main__":
    print(normalize(os.environ["IPA_URL"]))
