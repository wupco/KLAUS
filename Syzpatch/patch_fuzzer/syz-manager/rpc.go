// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type Relations struct {
	ArgIdx  int
	CallIdx int
	Poc     []byte
}

type RelationSigs struct {
	Mark bool
	Poc  []byte
}

type RPCServer struct {
	mgr                   RPCManagerView
	target                *prog.Target
	configEnabledSyscalls []int
	targetEnabledSyscalls map[*prog.Syscall]bool
	spliceEnabled         bool
	stats                 *Stats
	sandbox               string
	batchSize             int

	progSeed []byte

	corpusSyscall map[string]bool

	mu             sync.Mutex
	fuzzers        map[string]*Fuzzer
	checkResult    *rpctype.CheckArgs
	maxSignal      signal.Signal
	corpusSignal   signal.Signal
	Relation       *Relations
	RelationSig    *RelationSigs
	corpusObjSig   signal.Signal
	corpusPatchSig signal.PatchSig
	corpusTraceSig signal.Signal
	corpusCover    cover.Cover
	rotator        *prog.Rotator
	rnd            *rand.Rand
}

type Fuzzer struct {
	name          string
	inputs        []rpctype.RPCInput
	newMaxSignal  signal.Signal
	rotatedSignal signal.Signal
}

type BugFrames struct {
	memoryLeaks []string
	dataRaces   []string
}

// RPCManagerView restricts interface between RPCServer and Manager.
type RPCManagerView interface {
	fuzzerConnect() ([]rpctype.RPCInput, BugFrames)
	machineChecked(result *rpctype.CheckArgs, enabledSyscalls map[*prog.Syscall]bool)
	newInput(inp rpctype.RPCInput, sign signal.Signal) bool
	candidateBatch(size int) []rpctype.RPCCandidate
	rotateCorpus() bool
	SyncRelation() bool             //yh
	GetRelation() bool              //yh
	SyncRelationBuildingSeed() bool //yh
	GetRelationBuildingSig() bool   //yh
}

func startRPCServer(mgr *Manager) (int, error) {
	serv := &RPCServer{
		mgr:                   mgr,
		target:                mgr.target,
		configEnabledSyscalls: mgr.configEnabledSyscalls,
		spliceEnabled:         mgr.spliceEnabled,
		stats:                 mgr.stats,
		sandbox:               mgr.cfg.Sandbox,
		fuzzers:               make(map[string]*Fuzzer),
		rnd:                   rand.New(rand.NewSource(time.Now().UnixNano())),
		progSeed:              mgr.progSeed,
		Relation:              &Relations{-1, -1, nil},
		RelationSig:           &RelationSigs{false, nil},
		corpusSyscall:         make(map[string]bool),
	}
	serv.batchSize = 5
	if serv.batchSize < mgr.cfg.Procs {
		serv.batchSize = mgr.cfg.Procs
	}
	s, err := rpctype.NewRPCServer(mgr.cfg.RPC, "Manager", serv)
	if err != nil {
		return 0, err
	}
	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	port := s.Addr().(*net.TCPAddr).Port
	go s.Serve()
	return port, nil
}

func (serv *RPCServer) Connect(a *rpctype.ConnectArgs, r *rpctype.ConnectRes) error {
	log.Logf(1, "fuzzer %v connected", a.Name)
	serv.stats.vmRestarts.inc()

	corpus, bugFrames := serv.mgr.fuzzerConnect()

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := &Fuzzer{
		name: a.Name,
	}
	serv.fuzzers[a.Name] = f
	r.MemoryLeakFrames = bugFrames.memoryLeaks
	r.DataRaceFrames = bugFrames.dataRaces
	r.EnabledCalls = serv.configEnabledSyscalls
	r.GitRevision = prog.GitRevision
	r.TargetRevision = serv.target.Revision
	r.ProgSeed = serv.progSeed
	r.SpliceEnabled = serv.spliceEnabled
	// TODO: temporary disabled b/c we suspect this negatively affects fuzzing.
	if false && serv.mgr.rotateCorpus() && serv.rnd.Intn(3) != 0 {
		// We do rotation every other time because there are no objective
		// proofs regarding its efficiency either way.
		// Also, rotation gives significantly skewed syscall selection
		// (run prog.TestRotationCoverage), it may or may not be OK.
		r.CheckResult = serv.rotateCorpus(f, corpus)
	} else {
		r.CheckResult = serv.checkResult
		f.inputs = corpus
		f.newMaxSignal = serv.maxSignal.Copy()
	}
	return nil
}

func (serv *RPCServer) rotateCorpus(f *Fuzzer, corpus []rpctype.RPCInput) *rpctype.CheckArgs {
	// Fuzzing tends to stuck in some local optimum and then it fails to cover
	// other state space points since code coverage is only a very approximate
	// measure of logic coverage. To overcome this we introduce some variation
	// into the process which should cause steady corpus rotation over time
	// (the same coverage is achieved in different ways).
	//
	// First, we select a subset of all syscalls for each VM run (result.EnabledCalls).
	// This serves 2 goals: (1) target fuzzer at a particular area of state space,
	// (2) disable syscalls that cause frequent crashes at least in some runs
	// to allow it to do actual fuzzing.
	//
	// Then, we remove programs that contain disabled syscalls from corpus
	// that will be sent to the VM (f.inputs). We also remove 10% of remaining
	// programs at random to allow to rediscover different variations of these programs.
	//
	// Then, we drop signal provided by the removed programs and also 10%
	// of the remaining signal at random (f.newMaxSignal). This again allows
	// rediscovery of this signal by different programs.
	//
	// Finally, we adjust criteria for accepting new programs from this VM (f.rotatedSignal).
	// This allows to accept rediscovered varied programs even if they don't
	// increase overall coverage. As the result we have multiple programs
	// providing the same duplicate coverage, these are removed during periodic
	// corpus minimization process. The minimization process is specifically
	// non-deterministic to allow the corpus rotation.
	//
	// Note: at no point we drop anything globally and permanently.
	// Everything we remove during this process is temporal and specific to a single VM.
	calls := serv.rotator.Select()

	var callIDs []int
	callNames := make(map[string]bool)
	for call := range calls {
		callNames[call.Name] = true
		callIDs = append(callIDs, call.ID)
	}

	f.inputs, f.newMaxSignal = serv.selectInputs(callNames, corpus, serv.maxSignal)
	// Remove the corresponding signal from rotatedSignal which will
	// be used to accept new inputs from this manager.
	f.rotatedSignal = serv.corpusSignal.Intersection(f.newMaxSignal)

	result := *serv.checkResult
	result.EnabledCalls = map[string][]int{serv.sandbox: callIDs}
	return &result
}

func (serv *RPCServer) selectInputs(enabled map[string]bool, inputs0 []rpctype.RPCInput, signal0 signal.Signal) (
	inputs []rpctype.RPCInput, signal signal.Signal) {
	signal = signal0.Copy()
	for _, inp := range inputs0 {
		calls, _, err := prog.CallSet(inp.Prog)
		if err != nil {
			panic(fmt.Sprintf("rotateInputs: CallSet failed: %v\n%s", err, inp.Prog))
		}
		for call := range calls {
			if !enabled[call] {
				goto drop
			}
		}
		if serv.rnd.Float64() > 0.9 {
			goto drop
		}
		inputs = append(inputs, inp)
		continue
	drop:
		for _, sig := range inp.Signal.Elems {
			delete(signal, sig)
		}
	}
	signal.Split(len(signal) / 10)
	return inputs, signal
}

func (serv *RPCServer) Check(a *rpctype.CheckArgs, r *int) error {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	if serv.checkResult != nil {
		return nil
	}
	serv.targetEnabledSyscalls = make(map[*prog.Syscall]bool)
	for _, call := range a.EnabledCalls[serv.sandbox] {
		serv.targetEnabledSyscalls[serv.target.Syscalls[call]] = true
	}
	serv.mgr.machineChecked(a, serv.targetEnabledSyscalls)
	a.DisabledCalls = nil
	serv.checkResult = a
	serv.rotator = prog.MakeRotator(serv.target, serv.targetEnabledSyscalls, serv.rnd)
	return nil
}

func logSignal(signal signal.Signal) {
	for m := range signal {
		log.Logf(3, "Signal value: 0xffffffff%x\n", m)
	}
}

func (serv *RPCServer) SyncRelationBuildingSeed(a *rpctype.SyncRelationArgs, r *int) error {
	//log.Logf(0, "sync RelationBuildingSeed ok!")
	serv.RelationSig = &RelationSigs{
		Mark: true,
		Poc:  a.P,
	}
	//serv.Relation
	//serv.relation
	return nil
}

func (serv *RPCServer) GetRelationBuildingSig(a *rpctype.SyncRelationArgs, r *rpctype.GetRelRes) error {
	if serv.RelationSig.Mark == false {
		r.CallIdx = -2
		r.ArgIdx = -2
		r.Poc = nil
		return nil
	} else {
		//log.Logf(0, "GetRelationBuildingSig %v", serv.RelationSig.Poc)
		//log.Logf(0, "get relation ok!")
		r.CallIdx = -1
		r.ArgIdx = -1
		r.Poc = serv.RelationSig.Poc
		return nil
	}
}

func (serv *RPCServer) GetRelation(a *rpctype.SyncRelationArgs, r *rpctype.GetRelRes) error {
	if serv.Relation.Poc == nil {
		r.CallIdx = -1
		r.ArgIdx = -1
		r.Poc = nil
		return nil
	} else {
		//log.Logf(0, "get relation ok!")
		r.CallIdx = serv.Relation.CallIdx
		r.ArgIdx = serv.Relation.ArgIdx
		r.Poc = serv.Relation.Poc
		return nil
	}
}

func (serv *RPCServer) SyncRelation(a *rpctype.SyncRelationArgs, r *int) error {
	log.Logf(0, "sync rpc ok! callid: %d, argid: %d", a.CallIdx, a.ArgIdx)
	serv.Relation = &Relations{
		ArgIdx:  a.ArgIdx,
		CallIdx: a.CallIdx,
		Poc:     a.P,
	}
	//serv.Relation
	//serv.relation
	return nil
}

func (serv *RPCServer) NewInput(a *rpctype.NewInputArgs, r *int) error {
	inputSignal := a.Signal.Deserialize()
	inputObjSig := a.ObjSig.Deserialize()
	inputPatchSig := a.PatchSig.Deserialize()
	inputTraceSig := a.TraceSig.Deserialize()
	log.Logf(0, "new input from %v for syscall %v (signal=%v, patch signal=%v, object signal=%v, trace signal=%v, cover=%v)",
		a.Name, a.Call, inputSignal.Len(), inputPatchSig, inputObjSig.Len(), inputTraceSig.Len(), len(a.Cover))
	logSignal(inputObjSig)
	bad, disabled := checkProgram(serv.target, serv.targetEnabledSyscalls, a.RPCInput.Prog)
	if bad || disabled {
		log.Logf(0, "rejecting program from fuzzer (bad=%v, disabled=%v):\n%s", bad, disabled, a.RPCInput.Prog)
		return nil
	}
	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	genuine := !serv.corpusSignal.Diff(inputSignal).Empty()
	newObjSig := serv.corpusObjSig.Diff(inputObjSig)
	newObj := !newObjSig.Empty()
	newPatchSig := serv.corpusPatchSig.Diff(inputPatchSig)
	newPatch := !newPatchSig.Empty()
	newTraceSig := serv.corpusTraceSig.Diff(inputTraceSig)
	newTrace := !newTraceSig.Empty()
	if newPatch {
		log.Logf(0, "received new input with object signal : %v", newPatchSig)
	}
	newSyscall := false
	_, found := serv.corpusSyscall[a.Call]
	if !found {
		serv.corpusSyscall[a.Call] = true
		newSyscall = true
	}
	if newObj || newSyscall {
		log.Logf(0, "received new input from %v with object signal : %v, new : %v", a.Call, inputObjSig.Len(), newObjSig.Len())
	}
	rotated := false
	if !genuine && !newPatch && !newObj && !newTrace && f.rotatedSignal != nil {
		rotated = !f.rotatedSignal.Diff(inputSignal).Empty()
	}
	if !genuine && !newPatch && !newObj && !newTrace && !rotated && !newSyscall {
		return nil
	}
	if !serv.mgr.newInput(a.RPCInput, inputSignal) && !newSyscall {
		return nil
	}

	if f.rotatedSignal != nil {
		f.rotatedSignal.Merge(inputSignal)
	}
	serv.corpusCover.Merge(a.Cover)
	serv.stats.corpusCover.set(len(serv.corpusCover))
	serv.stats.newInputs.inc()
	if rotated {
		serv.stats.rotatedInputs.inc()
	}

	if genuine || newObj || newSyscall || newPatch || newTrace {
		serv.corpusSignal.Merge(inputSignal)
		serv.corpusObjSig.Merge(inputObjSig)
		serv.corpusPatchSig.Merge(inputPatchSig)
		serv.corpusTraceSig.Merge(inputTraceSig)
		//log.Logf(0, "serv.corpusPatchSig : %v", serv.corpusPatchSig)
		serv.stats.corpusSignal.set(serv.corpusSignal.Len())
		serv.stats.corpusObjSig.set(serv.corpusObjSig.Len())
		serv.stats.corpusTraceSig.set(serv.corpusTraceSig.Len())
		serv.stats.corpusPatchSig.set(serv.corpusPatchSig.Len())

		a.RPCInput.Cover = nil // Don't send coverage back to all fuzzers.
		for _, other := range serv.fuzzers {
			if other == f {
				continue
			}
			other.inputs = append(other.inputs, a.RPCInput)
		}
	}
	return nil
}

func (serv *RPCServer) Poll(a *rpctype.PollArgs, r *rpctype.PollRes) error {
	serv.stats.mergeNamed(a.Stats)

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	if f == nil {
		log.Fatalf("fuzzer %v is not connected", a.Name)
	}
	newMaxSignal := serv.maxSignal.Diff(a.MaxSignal.Deserialize())
	if !newMaxSignal.Empty() {
		serv.maxSignal.Merge(newMaxSignal)
		serv.stats.maxSignal.set(len(serv.maxSignal))
		for _, f1 := range serv.fuzzers {
			if f1 == f {
				continue
			}
			f1.newMaxSignal.Merge(newMaxSignal)
		}
	}
	r.MaxSignal = f.newMaxSignal.Split(500).Serialize()
	if a.NeedCandidates {
		log.Logf(3, "call for candidates from %s\n", a.Name)
		r.Candidates = serv.mgr.candidateBatch(serv.batchSize)
	}
	if len(r.Candidates) == 0 {
		batchSize := serv.batchSize
		// When the fuzzer starts, it pumps the whole corpus.
		// If we do it using the final batchSize, it can be very slow
		// (batch of size 6 can take more than 10 mins for 50K corpus and slow kernel).
		// So use a larger batch initially (we use no stats as approximation of initial pump).
		const initialBatch = 30
		if len(a.Stats) == 0 && batchSize < initialBatch {
			batchSize = initialBatch
		}
		for i := 0; i < batchSize && len(f.inputs) > 0; i++ {
			last := len(f.inputs) - 1
			r.NewInputs = append(r.NewInputs, f.inputs[last])
			f.inputs[last] = rpctype.RPCInput{}
			f.inputs = f.inputs[:last]
		}
		if len(f.inputs) == 0 {
			f.inputs = nil
		}
	}
	log.Logf(3, "poll from %v: candidates=%v inputs=%v maxsignal=%v",
		a.Name, len(r.Candidates), len(r.NewInputs), len(r.MaxSignal.Elems))
	return nil
}
