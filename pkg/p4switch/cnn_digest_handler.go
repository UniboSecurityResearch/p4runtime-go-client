package p4switch

import (
	"github.com/antoninbas/p4runtime-go-client/pkg/util/conversion"
	"context"
	"time"

	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
)

func (sw *GrpcSwitch) RealTimeReconfiguration(ctx context.Context){
	// change configuration of switch sw (in our case the new one has no digest or rules) and write success/failure message
	switchConfig, err := parseSwConfig(sw.GetName(), sw.configNameAlt)
	
	if err != nil {
		sw.log.Errorf("Cannot change configuration: " + err.Error())
	} else {
		err := sw.ChangeConfig(ctx, switchConfig)
		
		if err != nil {
			sw.log.Errorf("Cannot change configuration: " + err.Error())
		} else {
			sw.log.Debugf("Config updated to " + sw.configNameAlt)
		}
	}
	//adding necessary rules
	//sw.InitiateConfig(ctx, sw.configNameAlt)
}

func (sw *GrpcSwitch) handleDigestForCNN(ctx context.Context, digestList *p4_v1.DigestList, stateHandler *StateHandler) {
	for _, digestData := range digestList.Data {
		str := digestData.GetStruct()
		mode := int(conversion.BinaryCompressedToUint16(str.Members[0].GetBitstring()))	
		digestStruct := parseDigestData(str)
		digest := Digest{
					Ingress_timestamp: digestStruct.ingress_timestamp,
					Packet_length: digestStruct.packet_length,
					Ip_flags: digestStruct.ip_flags,
					Tcp_len: digestStruct.tcp_len,
					Tcp_ack: digestStruct.tcp_ack,
					Tcp_flags: digestStruct.tcp_flags,
					Tcp_window_size: digestStruct.tcp_window_size,
					Udp_len: digestStruct.udp_len,
					Icmp_type: digestStruct.icmp_type,
					SrcPort: digestStruct.srcPort,
					DstPort: digestStruct.dstPort,
					Src_ip: digestStruct.src_ip,
					Dst_ip: digestStruct.dst_ip,
					Ip_upper_protocol: digestStruct.ip_upper_protocol,
					Hitorsuspect: digestStruct.hitorsuspect,
				}
		//sw.log.Debugf("DIGEST hitorsuspect: %d", digestStruct.hitorsuspect)
		if mode == 0 && sw.GetNameOfPipeline() == "asymmetric_countmin.p4"{	//here: if swap == 0, if hitorsuspect == 2 installa flow sospetto
			if(digestStruct.swap == 0){
				if(digestStruct.hitorsuspect == 2){
					sw.log.Debugf("FLOW SUSPECT (src_ip -> dst_ip) %s -> %s", digestStruct.src_ip, digestStruct.dst_ip)
					//suspect flow found, will start monitor it from the next timeframe
					flow := Flow{
							Attacker: digestStruct.src_ip,
							Victim: digestStruct.dst_ip,
							Dropped: false,
							DDoS : 0,
						}
					// Adding a suspect flow, takes care of duplicates
					stateHandler.AddSuspectFlow(flow)	
				}
				stateHandler.AddDigest(digest)
			}else{
				sw.log.Infof("PHASE 1 - NUMBER of DIGESTS registered in this TIME FRAME: %d",len(stateHandler.GetDigests()))
				sw.RealTimeReconfiguration(ctx)
				for _, flow := range stateHandler.GetSuspectFlows() {
					sw.AddFlowToMonitorRules(ctx, flow)
				}
				stateHandler.ResetPhaseOne()
			}
		}
		if mode == 1 && sw.GetNameOfPipeline() == "p4_packet_management_countmin.p4"{	
			if(digestStruct.swap == 0){
				if(digestStruct.hitorsuspect == 2){
					sw.log.Debugf("FLOW SUSPECT %s -> %s", digestStruct.src_ip, digestStruct.dst_ip)
					flow := Flow{
						Attacker: digestStruct.src_ip,
						Victim: digestStruct.dst_ip,
						Dropped: false,
						DDoS : 0,
					}
					isPresent := stateHandler.AddSuspectFlow(flow)
					if isPresent == false {
						sw.AddFlowToMonitorRules(ctx, flow)
					}
				}				
				stateHandler.AddDigest(digest)	
			}else{
				if(time.Now().Unix() - stateHandler.currentStartingFrameTime > 30){
					sw.log.Infof("PHASE 2 - NUMBER of DIGESTS registered in this TIME FRAME: %d",len(stateHandler.GetDigests()))
					if( len(stateHandler.GetDigests()) == 0 ){
						sw.RealTimeReconfiguration(ctx)
						stateHandler.Reset()
					}		
					currentStartingTime := stateHandler.currentStartingFrameTime + 30
					stateHandler.ResetPhaseTwo(currentStartingTime)
				} 
			}
		}
	}
	if err := sw.p4RtC.AckDigestList(ctx, digestList); err != nil {
		sw.errCh <- err
	}

}

func parseDigestData(str *p4_v1.P4StructLike) digest_t {
        ingress_timestamp := conversion.BinaryCompressedToUint64(str.Members[1].GetBitstring())
        packet_length := conversion.BinaryCompressedToUint16(str.Members[2].GetBitstring())
        ip_flags := conversion.BinaryCompressedToUint16(str.Members[3].GetBitstring())
        tcp_len := conversion.BinaryCompressedToUint16(str.Members[4].GetBitstring())
        tcp_ack := conversion.BinaryCompressedToUint16(str.Members[5].GetBitstring())
        tcp_flags := conversion.BinaryCompressedToUint16(str.Members[6].GetBitstring())
        tcp_window_size := conversion.BinaryCompressedToUint16(str.Members[7].GetBitstring())
        udp_len := conversion.BinaryCompressedToUint16(str.Members[8].GetBitstring())
        icmp_type := conversion.BinaryCompressedToUint16(str.Members[9].GetBitstring())

        srcPort := conversion.BinaryCompressedToUint16(str.Members[10].GetBitstring())
        dstPort := conversion.BinaryCompressedToUint16(str.Members[11].GetBitstring())
        src_ip := conversion.BinaryToIpv4(str.Members[12].GetBitstring())
        dst_ip := conversion.BinaryToIpv4(str.Members[13].GetBitstring())
        ip_upper_protocol := conversion.BinaryCompressedToUint16(str.Members[14].GetBitstring())
        swap := conversion.BinaryCompressedToUint16(str.Members[15].GetBitstring())
        hitorsuspect := conversion.BinaryCompressedToUint16(str.Members[16].GetBitstring())

        return digest_t{
                ingress_timestamp: ingress_timestamp,
                packet_length: int(packet_length),
                ip_flags: int(ip_flags),
                tcp_len: int(tcp_len),
                tcp_ack: int(tcp_ack),
                tcp_flags: int(tcp_flags),
                tcp_window_size: int(tcp_window_size),
                udp_len: int(udp_len),
                icmp_type: int(icmp_type),
                srcPort: int(srcPort),
                dstPort: int(dstPort),
                src_ip: src_ip,
                dst_ip: dst_ip,
                ip_upper_protocol: int(ip_upper_protocol),
                swap: int(swap),
                hitorsuspect: int(hitorsuspect),
        }
}

