/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_ARP = 0x0806;
const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  PROTOCOL_ICMP = 0x01;
const bit<8>  PROTOCOL_TCP = 0x06;
const bit<8>  PROTOCOL_UDP = 0x11;
const bit<8>  ICMP_CODE_FAKE_TCP = 0xfd;
const bit<8>  ICMP_CODE_FAKE_UDP = 0xfe;
const bit<8>  ICMP_CODE_FAKE_ICMP = 0xff;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> hdrChecksum;
}

struct metadata {
    bit<1>  fake;
    bit<8>  originalProtocol;
    bit<8>  icmpFakeCode;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    icmp_t       icmp_outer;
    icmp_t       icmp_inner;
}

parser parse(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        meta.fake = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTOCOL_TCP: parse_tcp;
            PROTOCOL_UDP: parse_udp;
            PROTOCOL_ICMP: parse_icmp_outer;
            default: accept;
        }
    }

    state parse_tcp {
        meta.fake = 0;
        meta.originalProtocol = PROTOCOL_TCP;
        meta.icmpFakeCode = ICMP_CODE_FAKE_TCP;
        transition accept;
    }

    state parse_udp {
        meta.fake = 0;
        meta.originalProtocol = PROTOCOL_UDP;
        meta.icmpFakeCode = ICMP_CODE_FAKE_UDP;
        transition accept;
    }

    state parse_icmp_outer {
        packet.extract(hdr.icmp_outer);
        transition select(hdr.icmp_outer.code) {
            ICMP_CODE_FAKE_TCP: parse_fake_tcp;
            ICMP_CODE_FAKE_UDP: parse_fake_udp;
            ICMP_CODE_FAKE_ICMP: parse_fake_icmp;
            default: parse_icmp_inner;
        }
    }

    state parse_fake_tcp {
        meta.fake = 1;
        meta.originalProtocol = PROTOCOL_TCP;
        transition accept;
    }

    state parse_fake_udp {
        meta.fake = 1;
        meta.originalProtocol = PROTOCOL_UDP;
        transition accept;
    }

    state parse_fake_icmp {
        meta.fake = 1;
        meta.originalProtocol = PROTOCOL_ICMP;
        packet.extract(hdr.icmp_inner);
        transition accept;
    }

    state parse_icmp_inner {
        meta.fake = 0;
        meta.originalProtocol = PROTOCOL_ICMP;
        meta.icmpFakeCode = ICMP_CODE_FAKE_ICMP;
        hdr.icmp_inner.setValid();
        hdr.icmp_inner.type = hdr.icmp_outer.type;
        hdr.icmp_inner.code = hdr.icmp_outer.code;
        hdr.icmp_inner.hdrChecksum = hdr.icmp_outer.hdrChecksum;
        transition accept;
    }

 
}

control verifyChecksum(inout headers hdr, inout metadata meta) { 
    apply {  }
}

control ingress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    action encap() {
        hdr.ipv4.protocol = PROTOCOL_ICMP;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
        hdr.icmp_outer.setValid();
        hdr.icmp_outer.type = 0x08;
        hdr.icmp_outer.code = meta.icmpFakeCode;
        hdr.icmp_outer.hdrChecksum = 0x0000;
    }

    action decap() {
        hdr.icmp_outer.setInvalid();
        hdr.ipv4.protocol = meta.originalProtocol;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 4;
    }

    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table cap {
        key = {
            meta.fake: exact;
        }
        actions = {
            encap;
            decap;
            NoAction;
        }
        const entries = {
            0: encap();
            1: decap();
        }
        default_action = NoAction();
    }

    table ipv4 {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            forward;
            NoAction;
        }
        const entries = {
            1: forward(2);
            2: forward(1);
            3: forward(4);
            4: forward(3);
        }
        default_action = NoAction();
    }

    apply {
        cap.apply();
        ipv4.apply();
    }
}

control egress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

control computeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
       
        update_checksum(
            hdr.icmp_outer.isValid(),
            { hdr.icmp_outer.type,
              hdr.icmp_outer.code },
            hdr.icmp_outer.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control deparse(packet_out packet, in headers hdr) {
     apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp_outer);
        packet.emit(hdr.icmp_inner);
    }
}

V1Switch(
parse(),
verifyChecksum(),
ingress(),
egress(),
computeChecksum(),
deparse()
) main;
