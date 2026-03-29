#!/usr/bin/env python3
"""dns_packet - DNS packet builder and parser (RFC 1035)."""
import sys, json, struct, random

def encode_name(name):
    result = bytearray()
    for label in name.split("."):
        result.append(len(label))
        result.extend(label.encode())
    result.append(0)
    return bytes(result)

def decode_name(data, offset):
    labels = []; jumped = False; orig_offset = offset
    while True:
        length = data[offset]
        if length == 0: offset += 1; break
        if (length & 0xc0) == 0xc0:
            if not jumped: orig_offset = offset + 2
            ptr = struct.unpack(">H", data[offset:offset+2])[0] & 0x3fff
            offset = ptr; jumped = True; continue
        offset += 1
        labels.append(data[offset:offset+length].decode())
        offset += length
    return ".".join(labels), orig_offset if jumped else offset

def build_query(domain, qtype=1):
    txid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = encode_name(domain) + struct.pack(">HH", qtype, 1)
    return header + question

def parse_packet(data):
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    result = {"id": txid, "flags": f"0x{flags:04x}", "questions": qdcount,
              "answers": ancount, "authority": nscount, "additional": arcount}
    offset = 12
    questions = []
    for _ in range(qdcount):
        name, offset = decode_name(data, offset)
        qtype, qclass = struct.unpack(">HH", data[offset:offset+4])
        offset += 4
        questions.append({"name": name, "type": qtype, "class": qclass})
    result["question_records"] = questions
    answers = []
    for _ in range(ancount):
        name, offset = decode_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]; offset += rdlength
        rec = {"name": name, "type": rtype, "ttl": ttl}
        if rtype == 1 and rdlength == 4:
            rec["data"] = ".".join(str(b) for b in rdata)
        answers.append(rec)
    result["answer_records"] = answers
    return result

def main():
    print("DNS packet demo\n")
    query = build_query("example.com", qtype=1)
    print(f"  Query packet: {len(query)} bytes")
    print(f"  Hex: {query.hex()[:40]}...")
    parsed = parse_packet(query)
    print(f"  Parsed: {json.dumps(parsed, indent=2)}")
    # Build and parse a AAAA query
    q6 = build_query("google.com", qtype=28)
    p6 = parse_packet(q6)
    print(f"\n  AAAA query for google.com: type={p6['question_records'][0]['type']}")

if __name__ == "__main__":
    main()
