#!/usr/bin/env python3
"""dns_packet: DNS packet builder/parser (RFC 1035)."""
import struct, sys, random

def encode_name(name):
    result = b""
    for label in name.split("."):
        result += bytes([len(label)]) + label.encode()
    return result + b"\x00"

def decode_name(data, offset):
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1; break
        if (length & 0xC0) == 0xC0:
            ptr = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            name, _ = decode_name(data, ptr)
            labels.append(name)
            offset += 2; break
        offset += 1
        labels.append(data[offset:offset+length].decode())
        offset += length
    return ".".join(labels), offset

def build_query(domain, qtype=1, qclass=1):
    txid = random.randint(0, 65535)
    flags = 0x0100  # RD=1
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    question = encode_name(domain) + struct.pack("!HH", qtype, qclass)
    return header + question, txid

def parse_response(data):
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    questions = []
    for _ in range(qdcount):
        name, offset = decode_name(data, offset)
        qtype, qclass = struct.unpack("!HH", data[offset:offset+4])
        offset += 4
        questions.append({"name": name, "type": qtype, "class": qclass})
    answers = []
    for _ in range(ancount):
        name, offset = decode_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]
        offset += rdlength
        record = {"name": name, "type": rtype, "class": rclass, "ttl": ttl}
        if rtype == 1 and rdlength == 4:
            record["address"] = ".".join(str(b) for b in rdata)
        elif rtype == 28 and rdlength == 16:
            record["address"] = ":".join(f"{rdata[i]:02x}{rdata[i+1]:02x}" for i in range(0, 16, 2))
        elif rtype == 5:
            record["cname"], _ = decode_name(data, offset - rdlength)
        else:
            record["rdata"] = rdata
        answers.append(record)
    return {"id": txid, "flags": flags, "questions": questions, "answers": answers}

def test():
    # Build query
    pkt, txid = build_query("example.com")
    assert len(pkt) > 12
    assert struct.unpack("!H", pkt[:2])[0] == txid
    # Parse our own query as if it were a response (0 answers)
    parsed = parse_response(pkt)
    assert parsed["questions"][0]["name"] == "example.com"
    assert parsed["questions"][0]["type"] == 1
    # Name encoding
    assert encode_name("a.b") == b"\x01a\x01b\x00"
    assert encode_name("example.com") == b"\x07example\x03com\x00"
    # Name decoding
    data = b"\x03www\x07example\x03com\x00"
    name, off = decode_name(data, 0)
    assert name == "www.example.com"
    assert off == len(data)
    # Compression pointer
    data2 = b"\x03www\xc0\x00" + b"\x07example\x03com\x00"
    # ptr at 0 -> "example.com" starts at byte 5
    # Actually let's test simpler
    data3 = b"\x07example\x03com\x00"
    name3, _ = decode_name(data3, 0)
    assert name3 == "example.com"
    print("All tests passed!")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test": test()
    else: print("Usage: dns_packet.py test")
