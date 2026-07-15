import base64, sys

def convert(werkzeug_hash: str) -> str:
    method, rest = werkzeug_hash.split(":", 1)
    params, salt_b64, hash_hex = rest.split("$")
    N, r, p = params.split(":")
    log2_N = int(N).bit_length() - 1  # 32768 -> 15
    hash_b64 = base64.b64encode(bytes.fromhex(hash_hex)).decode()
    return f"$scrypt$ln={log2_N}$r={r}$p={p}${salt_b64}${hash_b64}"

if __name__ == "__main__":
    for line in sys.stdin:
        line = line.strip()
        if line:
            print(convert(line))
