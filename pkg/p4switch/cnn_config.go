package p4switch

import(
	"context"
)

func (sw *GrpcSwitch) AddFlowToMonitorRules(ctx context.Context, flow Flow){
	sw.log.Debugf("Adding rule to monitor flow (src: %v, dst: %v) ",flow.GetAttacker(), flow.GetVictim())

	rule := Rule{
		    	Table:       "MyIngress.ipv4_tag_and_drop",
				Keys:         []Key{ Key{Value:	flow.GetAttacker().String()},	
									 Key{Value:	flow.GetVictim().String()}},
				Action:      "NoAction",
				ActionParam: []string{},
			}
	entry, err := CreateTableEntry(sw, rule)
	if err != nil {
		sw.log.Errorf("Error inserting entry : %v", entry) 
	} else{
		sw.log.Infof("Entry: %v", entry) //
		sw.AddTableEntry(ctx,entry)
	}
}

func (sw *GrpcSwitch) DropFlowFromCNN(ctx context.Context, flow Flow){
	sw.log.Debugf("Adding rule to drop flow (src: %v, dst: %v) ",flow.GetAttacker(), flow.GetVictim())

	rule := Rule{
		    	Table:       "MyEgress.ipv4_drop",
				Keys:         []Key{ Key{Value:	flow.GetAttacker().String()},	
									 Key{Value:	flow.GetVictim().String()}},
				Action:      "MyEgress.drop",
				ActionParam: []string{},
			}
	entry, err := CreateTableEntry(sw, rule)
	if err != nil {
		sw.log.Errorf("Error inserting entry : %v", entry) 
	} else{
		sw.log.Infof("Entry: %v", entry) //
		sw.AddTableEntry(ctx,entry)
	}
}

func (sw *GrpcSwitch) UndropFlowFromCNN(ctx context.Context, flow Flow){
	sw.log.Debugf("Adding rule to undrop flow (src: %v, dst: %v) ",flow.GetAttacker(), flow.GetVictim())

	rule := Rule{
		    	Table:       "MyEgress.ipv4_drop",
				Keys:         []Key{ Key{Value:	flow.GetAttacker().String()},	
									 Key{Value:	flow.GetVictim().String()}},
				Action:      "MyEgress.drop",
				ActionParam: []string{},
			}
	entry, err := CreateTableEntry(sw, rule)
	if err != nil {
		sw.log.Errorf("Error inserting entry : %v", entry) 
	} else{
		sw.log.Infof("Entry: %v", entry) //
		sw.RemoveTableEntry(ctx,entry)
	}
}