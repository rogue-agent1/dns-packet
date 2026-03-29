#!/usr/bin/env python3
"""DNS packet builder and parser (simplified)."""
import struct, random

TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "TXT": 16, "NS": 2}
CLASSES = {"IN": 1}

def encode_name(name: str) -> bytes:
    result = bytearray()
    for label in name.rstrip(".").split("."):
        result.append(len(label))
        result.extend(label.encode("ascii"))
    result.append(0)
    return bytes(result)

def decode_name(data: bytes, offset: int) -> tuple:
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            pointer = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            name, _ = decode_name(data, pointer)
            labels.append(name)
            offset += 2
            return ".".join(labels) + ("." + name if labels else name), offset
        offset += 1
        labels.append(data[offset:offset+length].decode("ascii"))
        offset += length
    return ".".join(labels), offset

def build_query(name: str, qtype: str = "A") -> bytes:
    tid = random.randint(0, 65535)
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack("!HH", TYPES.get(qtype, 1), 1)
    return header + question

def parse_header(data: bytes) -> dict:
    tid, flags, qcount, acount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    return {"id": tid, "flags": flags, "questions": qcount, "answers": acount,
            "authority": nscount, "additional": arcount}

def test():
    name = encode_name("example.com")
    decoded, _ = decode_name(name, 0)
    assert decoded == "example.com", f"{decoded}"
    q = build_query("google.com", "A")
    h = parse_header(q)
    assert h["questions"] == 1
    assert h["answers"] == 0
    name2 = encode_name("sub.domain.example.org")
    d2, _ = decode_name(name2, 0)
    assert d2 == "sub.domain.example.org"
    print("  dns_packet: ALL TESTS PASSED")

if __name__ == "__main__":
    test()
