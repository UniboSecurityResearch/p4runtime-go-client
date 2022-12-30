package server

import(
	"github.com/antoninbas/p4runtime-go-client/pkg/p4switch"
	"encoding/json"
	"context"

	"net/http"
	"io/ioutil"
)

func GetSuspectFlows(stateHandler *p4switch.StateHandler) func(w http.ResponseWriter, r *http.Request) {
	return func (w http.ResponseWriter, r *http.Request){
					w.Header().Set("Access-Control-Allow-Origin", "*")
			    	json.NewEncoder(w).Encode(stateHandler.GetSuspectFlows())
				}
}

func GetCollectedDigests(stateHandler *p4switch.StateHandler) func(w http.ResponseWriter, r *http.Request) {
	return func (w http.ResponseWriter, r *http.Request){
					w.Header().Set("Access-Control-Allow-Origin", "*")
				    json.NewEncoder(w).Encode(stateHandler.GetDigests())
		   		}
}

//missing the rule installation

func DropFlow(stateHandler *p4switch.StateHandler, switches []*p4switch.GrpcSwitch, ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func (w http.ResponseWriter, r *http.Request){
					reqBody, _ := ioutil.ReadAll(r.Body)
				    var flow p4switch.Flow 
				    json.Unmarshal(reqBody, &flow)
				    //flowSaved := stateHandler.GetFlowCorrespondingToArgument(flow)
				    //stringDebug := fmt.Sprintf("DROP FLOW - Dropped: %t Flow (src -> dst) %s -> %s\n", flowSaved.GetDropped(), flowSaved.GetAttacker().String(), flowSaved.GetVictim().String())
					//fmt.Printf(stringDebug)
					if(stateHandler.IsFlowDropped(flow) == false){
						for _,sw := range switches{
					    	//drop/undrop rules coming from CNN must be listened only on the second phase
					    	if(sw.GetNameOfPipeline() == "p4_packet_management_countmin.p4"){
					    		sw.DropFlowFromCNN(ctx,flow)
					    	}
					    }
					    flow.DropFlow()
						stateHandler.UpdateSuspectFlow(flow)
					}				    
				    json.NewEncoder(w).Encode(flow)
				}
}

func UpdateDroppedFlow(stateHandler *p4switch.StateHandler) func(w http.ResponseWriter, r *http.Request) {
	return func (w http.ResponseWriter, r *http.Request){
					reqBody, _ := ioutil.ReadAll(r.Body)
				    var flow p4switch.Flow 
				    json.Unmarshal(reqBody, &flow)
				    flowSaved := stateHandler.GetFlowCorrespondingToArgument(flow)
				    //stringDebug := fmt.Sprintf("UPDATE FLOW - Dropped: %t Flow (src -> dst) %s -> %s\n", flowSaved.GetDropped(), flowSaved.GetAttacker().String(), flowSaved.GetVictim().String())
				    //fmt.Printf(stringDebug)
				    flow.SetDropped(flowSaved.GetDropped()) //to keep track of dropped flows
				    stateHandler.UpdateSuspectFlow(flow)
				    json.NewEncoder(w).Encode(flow)
				}
}

func UndropFlow(stateHandler *p4switch.StateHandler, switches []*p4switch.GrpcSwitch, ctx context.Context) func(w http.ResponseWriter, r *http.Request) {
	return func (w http.ResponseWriter, r *http.Request){
					reqBody, _ := ioutil.ReadAll(r.Body)
				    var flow p4switch.Flow 
				    json.Unmarshal(reqBody, &flow)
				    if(stateHandler.IsFlowDropped(flow) == true){
						for _,sw := range switches{
					    	//drop/undrop rules coming from CNN must be listened only on the second phase
					    	if(sw.GetNameOfPipeline() == "p4_packet_management_countmin.p4"){
					    		sw.UndropFlowFromCNN(ctx,flow)
					    	}
					    }
					    flow.UndropFlow()
					    stateHandler.UpdateSuspectFlow(flow)
					}
				    json.NewEncoder(w).Encode(flow)
				}	
}