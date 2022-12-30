package p4switch

import (
	"context"
	"fmt"
	"time"

	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
)

var digestConfig p4_v1.DigestEntry_Config = p4_v1.DigestEntry_Config{
	MaxTimeoutNs: 0,
	MaxListSize:  1,
	AckTimeoutNs: time.Second.Nanoseconds() * 1000,
}

func (sw *GrpcSwitch) EnableDigest(ctx context.Context) error {
	digestName := sw.GetDigests()
	for _, digest := range digestName {
		if digest == "" {
			continue
		}
		if err := sw.p4RtC.EnableDigest(ctx,digest, &digestConfig); err != nil {
			return fmt.Errorf("cannot enable digest %s", digest)
		}
		sw.log.Debugf("Enabled digest %s", digest)
	}
	return nil
}

func (sw *GrpcSwitch) HandleDigest(ctx context.Context, digestList *p4_v1.DigestList, stateHandler *StateHandler) {
	
	//sw.log.Debugf("Switch Pipeline Name: " + sw.GetNameOfPipeline())
	//modifica funzione GetNameOfPipeline
	if(sw.GetNameOfPipeline() == "asymmetric_countmin.p4" || 
	   sw.GetNameOfPipeline() == "p4_packet_management_countmin.p4"){
		sw.handleDigestForCNN(ctx, digestList, stateHandler)
		//sw.log.Trace("Ack digest list. Handled by module cnn_digest_handler")
	} else{
			sw.log.Trace("Ack digest list. Not handled.")
	}
	if err := sw.p4RtC.AckDigestList(ctx,digestList); err != nil {
		sw.errCh <- err
	}
}