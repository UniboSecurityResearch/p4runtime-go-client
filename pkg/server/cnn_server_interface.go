package server

import(
	"github.com/antoninbas/p4runtime-go-client/pkg/p4switch"
	"encoding/json"

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

func DropFlow(stateHandler *p4switch.StateHandler) func(w http.ResponseWriter, r *http.Request) {
	return func (w http.ResponseWriter, r *http.Request){
					reqBody, _ := ioutil.ReadAll(r.Body)
				    var flow p4switch.Flow 
				    json.Unmarshal(reqBody, &flow)
				    flow.DropFlow()
				    stateHandler.UpdateSuspectFlow(flow)
				    json.NewEncoder(w).Encode(flow)
				}
}

func UpdateDroppedFlow(stateHandler *p4switch.StateHandler) func(w http.ResponseWriter, r *http.Request) {
	return func (w http.ResponseWriter, r *http.Request){
					reqBody, _ := ioutil.ReadAll(r.Body)
				    var flow p4switch.Flow 
				    json.Unmarshal(reqBody, &flow)
				    stateHandler.UpdateSuspectFlow(flow)
				    json.NewEncoder(w).Encode(flow)
				}
}

func UndropFlow(stateHandler *p4switch.StateHandler) func(w http.ResponseWriter, r *http.Request) {
	return func (w http.ResponseWriter, r *http.Request){
					reqBody, _ := ioutil.ReadAll(r.Body)
				    var flow p4switch.Flow 
				    json.Unmarshal(reqBody, &flow)
				    stateHandler.RemoveSuspectFlow(flow)
				    json.NewEncoder(w).Encode(flow)
				}	
}