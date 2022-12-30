package p4switch

import(
    "time"
    "net"
    "bytes"
    "io"
    "encoding/json"
    "fmt"
    "math"
)

//boilercode to process structs

func (cw *CounterWr) Write(p []byte) (n int, err error) {
    n, err = cw.Writer.Write(p)
    cw.Count += n
    return
}

func round(num float64) int {
    return int(num + math.Copysign(0.5, num))
}

func toFixed(num float64, precision int) float64 {
    output := math.Pow(10, float64(precision))
    return float64(round(num * output)) / output
}

type CounterWr struct {
    io.Writer
    Count int
}
//End of boilercode

type Flow struct {
	Attacker net.IP `json:"attacker"`
	Victim net.IP `json:"victim"`
    Dropped bool 
	DDoS float64 `json:"ddos"`
}

func (flow *Flow) GetAttacker() net.IP {
	return flow.Attacker
}

func (flow *Flow) GetVictim() net.IP {
	return flow.Victim
}

func (flow *Flow) isDropped() bool {
    return flow.Dropped
}

func (flow *Flow) DropFlow() {
    flow.Dropped = true
}

func (flow *Flow) UndropFlow() {
    flow.Dropped = false
}


type Digest struct {
    Ingress_timestamp  uint64    `json:"ingress_timestamp"`
    Packet_length   int `json:"packet_length"`
    Ip_flags    int `json:"ip_flags"`
    Tcp_len int `json:"tcp_len"`
    Tcp_ack int `json:"tcp_ack"`
    Tcp_flags int `json:"tcp_flags"`
    Tcp_window_size int `json:"tcp_window_size"`
    Udp_len int `json:"udp_len"`
    Icmp_type int `json:"icmp_type"`

    SrcPort int `json:"srcPort"`
    DstPort int `json:"dstPort"`
    Src_ip  net.IP `json:"src_ip"`
    Dst_ip  net.IP `json:"dst_ip"`
    Ip_upper_protocol int `json:"ip_upper_protocol"`   
    Hitorsuspect int `json:"hitorsuspect"`
}

type digest_t struct {
        ingress_timestamp uint64
        packet_length int
        ip_flags int
        tcp_len int
        tcp_ack int
        tcp_flags int
        tcp_window_size int
        udp_len int
        icmp_type int
        srcPort int
        dstPort int
        src_ip net.IP
        dst_ip net.IP
        ip_upper_protocol int
        swap int
        hitorsuspect int
}

func Contains(flows []Flow, flow Flow) bool {
    for _, f := range flows {
        if f.GetAttacker().Equal(flow.GetAttacker()) && f.GetVictim().Equal(flow.GetVictim()) {
            return true
        }
    }
    return false
}

func AreTheSameFlow(flow Flow, f Flow) bool {
    if f.GetAttacker().Equal(flow.GetAttacker()) && f.GetVictim().Equal(flow.GetVictim()) { //|| f.GetAttacker().Equal(flow.GetVictim()) && f.GetVictim().Equal(flow.GetAttacker())
        return true
    }
    return false
}

type StateHandler struct {
	digests []Digest
    suspectFlows []Flow
    currentStartingFrameTime int64
}

func (sh *StateHandler) GetDigestsSize() string {
	var size = len(sh.digests)
	if size > 0 {

		buf := &bytes.Buffer{}

		// Any writer, not just a buffer!
		var out io.Writer = buf
		cw := &CounterWr{Writer: out}

		if err := json.NewEncoder(cw).Encode(sh.digests); err != nil {
			panic(err)
		}

		digestsSize := fmt.Sprintf("%.2f", toFixed( float64(buf.Len())/1000000.0, 2 ))
		return digestsSize
	}
	return "0.00"
}

func CreateStateHandler() *StateHandler{
	return &StateHandler{
		digests: []Digest{},
        suspectFlows: []Flow{},
        currentStartingFrameTime: time.Now().Unix(),
	}
}

func (sh *StateHandler) GetSuspectFlows() []Flow{ //returns list of current suspect DDoS flows 
    return sh.suspectFlows
}

func (sh *StateHandler) GetDigests() []Digest{ //returns list of current suspect DDoS flows 
    return sh.digests
}

func (sh *StateHandler) AddDigest(digest Digest) {
    sh.digests = append(sh.digests, digest)
}

func (sh *StateHandler) AddSuspectFlow(flow Flow) bool { //returns True if flow is present
    if(Contains(sh.suspectFlows, flow) == false){
        sh.suspectFlows = append(sh.suspectFlows, flow)
        return false
    }
    return true
}

func (sh *StateHandler) RemoveSuspectFlow(flow Flow) {
    if(Contains(sh.suspectFlows, flow) == true){
        suspectFlows := []Flow{}
        for _,f := range sh.suspectFlows{
            if !AreTheSameFlow(flow,f) {
                suspectFlows = append(suspectFlows,f)
            }
        }
        sh.suspectFlows = suspectFlows
    }
}

func (sh *StateHandler) Reset() {
    sh.digests = []Digest{}
    sh.suspectFlows = []Flow{}
    sh.currentStartingFrameTime = time.Now().Unix()
}

func (sh *StateHandler) UpdateSuspectFlow(flow Flow) {
    suspectFlows := []Flow{}
    for _,f := range sh.suspectFlows{
        if AreTheSameFlow(flow,f) {
            suspectFlows = append(suspectFlows,flow)
        }
    }
    sh.suspectFlows = suspectFlows
}

