from dns_packet import build_query, encode_name, decode_name, DNSHeader
pkt = build_query("example.com", "A")
assert len(pkt) > 12
name_bytes = encode_name("example.com")
decoded, _ = decode_name(name_bytes, 0)
assert decoded == "example.com"
h, _ = DNSHeader.unpack(pkt)
assert h.qdcount == 1
print("DNS packet tests passed")