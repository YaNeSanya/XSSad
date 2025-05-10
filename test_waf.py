# test_waf.py
from engine.wafdetector import detect_waf_flag

# Моделируем ответы
tests = [
    {
        'name': 'CloudFlare (should detect)',
        'response': {
            'status': 403,
            'headers': 'cf-ray: abcdef\nsome: header',
            'text': 'Attention Required! | Cloudflare'
        }
    },
    {
        'name': 'AWS WAF (should detect)',
        'response': {
            'status': 403,
            'headers': 'x-amzn-requestid: 12345',
            'text': 'OK'
        }
    },
    {
        'name': 'No WAF (should be None)',
        'response': {
            'status': 200,
            'headers': 'server: nginx',
            'text': '<html>hello</html>'
        }
    }
]

for test in tests:
    wf = detect_waf_flag(test['response'])
    print(f"{test['name']}: -> {wf}")