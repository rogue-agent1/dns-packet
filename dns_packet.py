#!/usr/bin/env python3
"""dns_packet - DNS packet builder and parser."""
import sys, struct, random

TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2, "TXT": 16, "SOA": 6}
CLASSES = {"IN": 1}

def encode_name(name):
    result = bytearray()
    for label in name.rstrip(".").split("."):
        result.append(len(label))
        result.extend(label.encode())
    result.append(0)
    return bytes(result)

def decode_name(data, offset):
    labels = []
    jumped = False
    orig_offset = offset
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if not jumped:
                orig_offset = offset + 2
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode())
        offset += length
    return ".".join(labels), orig_offset if jumped else offset

def build_query(name, qtype="A", qid=None):
    if qid is None:
        qid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack(">HH", TYPES.get(qtype, 1), 1)
    return header + question

def parse_header(data):
    qid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    return {"id": qid, "flags": flags, "questions": qdcount, "answers": ancount,
            "authority": nscount, "additional": arcount}

def test():
    enc = encode_name("example.com")
    assert enc == b"\x07example\x03com\x00"
    name, offset = decode_name(enc, 0)
    assert name == "example.com"
    assert offset == len(enc)
    q = build_query("example.com", "A", qid=0x1234)
    assert len(q) > 12
    h = parse_header(q)
    assert h["id"] == 0x1234
    assert h["questions"] == 1
    enc2 = encode_name("sub.domain.example.com")
    name2, _ = decode_name(enc2, 0)
    assert name2 == "sub.domain.example.com"
    enc3 = encode_name("a.b")
    assert enc3 == b"\x01a\x01b\x00"
    print("All tests passed!")

if __name__ == "__main__":
    test() if "--test" in sys.argv else print("dns_packet: DNS packet builder. Use --test")
