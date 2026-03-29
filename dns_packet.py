#!/usr/bin/env python3
"""DNS packet encoder/decoder. Zero dependencies."""
import struct, sys, random

TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}
RTYPES = {v: k for k, v in TYPES.items()}

class DNSHeader:
    def __init__(self, id=None, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, rcode=0,
                 qdcount=0, ancount=0, nscount=0, arcount=0):
        self.id = id or random.randint(0, 65535)
        self.qr = qr; self.opcode = opcode; self.aa = aa; self.tc = tc
        self.rd = rd; self.ra = ra; self.rcode = rcode
        self.qdcount = qdcount; self.ancount = ancount
        self.nscount = nscount; self.arcount = arcount

    def pack(self):
        flags = (self.qr<<15)|(self.opcode<<11)|(self.aa<<10)|(self.tc<<9)|(self.rd<<8)|(self.ra<<7)|self.rcode
        return struct.pack(">HHHHHH", self.id, flags, self.qdcount, self.ancount, self.nscount, self.arcount)

    @staticmethod
    def unpack(data, offset=0):
        id, flags, qd, an, ns, ar = struct.unpack_from(">HHHHHH", data, offset)
        h = DNSHeader(id=id, qdcount=qd, ancount=an, nscount=ns, arcount=ar)
        h.qr = (flags>>15)&1; h.opcode = (flags>>11)&0xF; h.rcode = flags&0xF
        h.rd = (flags>>8)&1; h.ra = (flags>>7)&1
        return h, offset+12

def encode_name(name):
    parts = name.rstrip(".").split(".")
    result = b""
    for p in parts:
        result += bytes([len(p)]) + p.encode()
    return result + b"\x00"

def decode_name(data, offset):
    parts = []; jumped = False; saved = 0
    while True:
        if offset >= len(data): break
        length = data[offset]
        if length == 0: offset += 1; break
        if (length & 0xC0) == 0xC0:
            if not jumped: saved = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset+1]
            jumped = True; continue
        offset += 1
        parts.append(data[offset:offset+length].decode())
        offset += length
    return ".".join(parts), saved if jumped else offset

def build_query(name, qtype="A"):
    header = DNSHeader(qdcount=1)
    q = encode_name(name) + struct.pack(">HH", RTYPES.get(qtype, 1), 1)
    return header.pack() + q

def parse_response(data):
    header, offset = DNSHeader.unpack(data)
    questions = []
    for _ in range(header.qdcount):
        name, offset = decode_name(data, offset)
        qtype, qclass = struct.unpack_from(">HH", data, offset)
        offset += 4
        questions.append({"name": name, "type": TYPES.get(qtype, str(qtype))})
    answers = []
    for _ in range(header.ancount):
        name, offset = decode_name(data, offset)
        atype, aclass, ttl, rdlength = struct.unpack_from(">HHIH", data, offset)
        offset += 10
        rdata = data[offset:offset+rdlength]
        offset += rdlength
        value = ""
        if atype == 1 and rdlength == 4:
            value = ".".join(str(b) for b in rdata)
        elif atype == 28 and rdlength == 16:
            value = ":".join(f"{rdata[i]:02x}{rdata[i+1]:02x}" for i in range(0, 16, 2))
        answers.append({"name": name, "type": TYPES.get(atype, str(atype)), "ttl": ttl, "value": value})
    return {"header": header, "questions": questions, "answers": answers}

if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    pkt = build_query(name)
    print(f"Query packet for {name}: {len(pkt)} bytes")
    print(f"Hex: {pkt.hex()}")
