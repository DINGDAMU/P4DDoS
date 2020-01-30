#include <core.p4>
#include <v1model.p4>


header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udplen;
    bit<16> udpchk;
}

struct metadata {
    bit<64> nhop_ipv4;
    bit<64> buc_sum;
    bit<64> buc_val;
    bit<64> power_sum;
    bit<64> log_sum;
    bit<64> log_S;
    bit<64> buc_sumR1;
    bit<64> buc_sumR2;
    bit<32> log_value;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".tcp") 
    tcp_t      tcp;
    @name(".udp") 
    udp_t      udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".rewrite_mac") action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    @name(".send_frame") table send_frame {
        actions = {
            rewrite_mac;
            _drop;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
    }
    apply {
        send_frame.apply();
    }
}


register<bit<64>>(32w2)  thresholdReg;
register<bit<64>>(32w1)  min;
register<bit<64>>(32w1)  ewmaReg;

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    @name(".ipv4_forward") action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    action do_logES() {
        meta.buc_val = meta.buc_sum | (meta.buc_sum >> 1);
        meta.buc_val = meta.buc_val | (meta.buc_val >> 2);
        meta.buc_val = meta.buc_val | (meta.buc_val >> 4);
        meta.buc_val = meta.buc_val | (meta.buc_val >> 8);
        meta.buc_val = meta.buc_val | (meta.buc_val >> 16);
        meta.buc_val = meta.buc_val | (meta.buc_val >> 32);
        meta.buc_val = (meta.buc_val & 64w0x5555555555555555) + ((meta.buc_val >> 1) & 64w0x5555555555555555);
        meta.buc_val = (meta.buc_val & 64w0x3333333333333333) + ((meta.buc_val >> 2) & 64w0x3333333333333333);
        meta.buc_val = (meta.buc_val & 64w0xf0f0f0f0f0f0f0f) + ((meta.buc_val >> 4) & 64w0xf0f0f0f0f0f0f0f);
        meta.buc_val = (meta.buc_val & 64w0xff00ff00ff00ff) + ((meta.buc_val >> 8) & 64w0xff00ff00ff00ff);
        meta.buc_val = (meta.buc_val & 64w0xffff0000ffff) + ((meta.buc_val >> 16) & 64w0xffff0000ffff);
        meta.buc_val = (meta.buc_val & 64w0xffffffff) + ((meta.buc_val >> 32) & 64w0xffffffff);
            }


    action do_logES_dec() {
            meta.log_sum = (bit<64>)((meta.buc_val - 64w1) << 10);
           meta.buc_sumR1 = meta.buc_sum ^ (meta.buc_sum >> 8w1);
           meta.buc_sumR2 = meta.buc_sum ^ (meta.buc_sum >> 8w2);
            if (meta.buc_sum < meta.buc_sumR1 ){
                if(meta.buc_sum > meta.buc_sumR2){
                    meta.log_sum = meta.log_sum + 64w330;
                }
            }else {
                if (meta.buc_sum < meta.buc_sumR2) {
                    meta.log_sum = meta.log_sum + 64w599;
                }
            else {
                meta.log_sum = meta.log_sum + 64w827;
            }
        }

    }

   action do_logES_dec2() {
            meta.log_S = (bit<64>)((meta.buc_val - 64w1) << 10);
           meta.buc_sumR1 = meta.buc_sum ^ (meta.buc_sum >> 8w1);
           meta.buc_sumR2 = meta.buc_sum ^ (meta.buc_sum >> 8w2);
            if (meta.buc_sum < meta.buc_sumR1 ){
                if(meta.buc_sum > meta.buc_sumR2){
                    meta.log_S = meta.log_S + 64w330;
                }
            }else {
                if (meta.buc_sum < meta.buc_sumR2) {
                    meta.log_S = meta.log_S + 64w599;
                }
            else {
                meta.log_S = meta.log_S + 64w827;
            }
        }

  
    }

      


    @name(".ipv4_lpm") table ipv4_lpm {
        actions = {
            ipv4_forward;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
       table logES{
        actions = {
            do_logES;
        }
    }
    table logES2{
        actions = {
            do_logES;
        }
    }
     table logES_dec{
        actions = {
            do_logES_dec;
        }
    }
    table logES_dec2{
        actions = {
            do_logES_dec2;
        }
    }
     apply {
     // Hnorm obtained from P4Entropy
        bit<64> Hnorm;
     // Number of source IPs obtained from P4LogLog
        bit<64> nsrc;
     // Number of destination IPs obtained from P4LogLog
        bit<64> ndst;

    // threshold of N_norm
        bit<64> T_norm;
    // threshold of T_asym
        bit<64> T_asym;
         
        bit<64> log2nsrc;
        bit<64> log2ndst;
        bit<64> log2diff;
        bit<64> eta_min;
        bit<64> ewma;
        bit<64> logdiff;

        bit<1> Alarm_norm;
        bit<1> Alarm_asym;
        bit<1> Alarm_ddos;
     
     Alarm_norm = 0;
     Alarm_asym = 0;
     Alarm_ddos = 0;
     Hnorm = 512;
     nsrc = 15346;
     ndst = 12455;
     thresholdReg.read(T_norm, 0);
     thresholdReg.read(T_asym, 1);
     min.read(eta_min, 0);
     ewmaReg.read(ewma,0);
     meta.buc_sum = nsrc;
     logES.apply();
     logES_dec.apply();
     log2nsrc = meta.log_sum;
     meta.buc_sum = ndst;
     logES2.apply();
     logES_dec2.apply();
     log2ndst = meta.log_S;
     logdiff = log2nsrc -log2ndst;
     if(eta_min > 0){
     if (logdiff > T_asym){
            Alarm_asym = 1;
     }else{
        if(logdiff < eta_min){
            eta_min = logdiff;
        }
           }
     }else{
        eta_min = logdiff;
     }

    min.write(0, eta_min);
    // theta = 0.003
    // log2(1+theta) = 4
    T_asym = 4 + eta_min; 
    thresholdReg.write(1, T_asym);

     if (Hnorm < T_norm){
        Alarm_norm = 1;
     }else{
        if (ewma > 0){
            // alpha = 0.13 << 10 = 133
            ewma = 133*Hnorm + 891* ewma;
        }else{
            ewma = Hnorm;
        }
        // epsilon = 0.002
        T_norm = ewma - 2;
        ewmaReg.write(0, ewma);
        thresholdReg.write(0, T_norm);
     }
     if (Alarm_norm == 1 && Alarm_asym == 1){
        Alarm_ddos = 1;
     }

        ipv4_lpm.apply();
      }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

