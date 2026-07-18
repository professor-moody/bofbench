package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEDRGuidanceRequiresExplicitExistingObservation(t *testing.T){
	d:=t.TempDir();p:=filepath.Join(d,"guidance.json");raw:=[]byte(`{"schema_version":"windows.build-guidance/v1","applicability":{"product":"defender"},"observations":[{"id":"abi-1"}]}`);if err:=os.WriteFile(p,raw,0600);err!=nil{t.Fatal(err)};g,copied,err:=loadEDRGuidance(p,[]string{"abi-1"});if err!=nil{t.Fatal(err)};if g.SchemaVersion!="windows.build-guidance/v1"||len(g.ObservationIDs)!=1||string(copied)!=string(raw){t.Fatalf("unexpected guidance: %+v",g)};if _,_,err=loadEDRGuidance(p,[]string{"missing"});err==nil{t.Fatal("missing observation accepted")}
}
