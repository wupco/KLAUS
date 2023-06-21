// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

type Fuzzer struct {
	name              string
	outputType        OutputType
	config            *ipc.Config
	execOpts          *ipc.ExecOpts
	procs             []*Proc
	gate              *ipc.Gate
	workQueue         *WorkQueue
	needPoll          chan struct{}
	choiceTable       *prog.ChoiceTable
	corpusChoiceTable *prog.ChoiceTable
	stats             [StatCount]uint64
	manager           *rpctype.RPCClient
	target            *prog.Target
	triagedCandidates uint32

	faultInjectionEnabled    bool
	comparisonTracingEnabled bool
	spliceEnabled            bool

	corpusMu     sync.RWMutex
	ctMu         sync.RWMutex
	corpus       []*prog.Prog
	corpusHashes map[hash.Sig]struct{}
	corpusPrios  []int64
	sumPrios     int64

	signalMu     sync.RWMutex
	corpusSignal signal.Signal // signal of inputs in corpus
	maxSignal    signal.Signal // max signal ever observed including flakes
	newSignal    signal.Signal // diff of maxSignal since last sync with master

	corpusObjSignal signal.Signal
	maxObjSignal    signal.Signal
	newObjSignal    signal.Signal
	corpusSyscall   map[string]bool

	corpusTraceSignal signal.Signal
	maxTraceSignal    signal.Signal
	newTraceSignal    signal.Signal

	corpusPatchSignal signal.PatchSig
	maxPatchSignal    signal.PatchSig
	newPatchSignal    signal.PatchSig
	Counter           int
	Ctrlnum           int
	var_arg_map       map[uint32][]int
	variableHashes    map[uint32]map[uint64]bool // map of variable hashes
	variableHashesRes map[uint32][]map[int]int   // map of variable hashes result
	condHashes        map[uint32]map[uint32]bool
	condHashesRes     map[uint32]bool

	logMu sync.Mutex
}

type FuzzerSnapshot struct {
	corpus      []*prog.Prog
	corpusPrios []int64
	sumPrios    int64
}

type Stat int

const (
	StatGenerate Stat = iota
	StatFuzz
	StatCandidate
	StatTriage
	StatMinimize
	StatSmash
	StatHint
	StatSeed
	StatCount
)

var statNames = [StatCount]string{
	StatGenerate:  "exec gen",
	StatFuzz:      "exec fuzz",
	StatCandidate: "exec candidate",
	StatTriage:    "exec triage",
	StatMinimize:  "exec minimize",
	StatSmash:     "exec smash",
	StatHint:      "exec hints",
	StatSeed:      "exec seeds",
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

func createIPCConfig(features *host.Features, config *ipc.Config) {
	if features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	config.Flags |= ipc.FlagEnableNetReset
	config.Flags |= ipc.FlagEnableCgroups
	config.Flags |= ipc.FlagEnableCloseFds
	if features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}
	if features[host.FeatureVhciInjection].Enabled {
		config.Flags |= ipc.FlagEnableVhciInjection
	}
}

// nolint: funlen
func main() {
	debug.SetGCPercent(50)

	var (
		flagName    = flag.String("name", "test", "unique name for manager")
		flagOS      = flag.String("os", runtime.GOOS, "target OS")
		flagArch    = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager = flag.String("manager", "", "manager rpc address")
		flagProcs   = flag.Int("procs", 1, "number of parallel test processes")
		flagOutput  = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagPprof   = flag.String("pprof", "", "address to serve pprof profiles")
		flagTest    = flag.Bool("test", false, "enable image testing mode")      // used by syz-ci
		flagRunTest = flag.Bool("runtest", false, "enable program testing mode") // used by pkg/runtest
	)
	flag.Parse()
	outputType := parseOutputType(*flagOutput)
	log.Logf(0, "fuzzer started")

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("failed to create default ipc config: %v", err)
	}
	sandbox := ipc.FlagsToSandbox(config.Flags)
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	checkArgs := &checkArgs{
		target:      target,
		sandbox:     sandbox,
		ipcConfig:   config,
		ipcExecOpts: execOpts,
	}
	if *flagTest {
		testImage(*flagManager, checkArgs)
		return
	}

	if *flagPprof != "" {
		go func() {
			err := http.ListenAndServe(*flagPprof, nil)
			log.Fatalf("failed to serve pprof profiles: %v", err)
		}()
	} else {
		runtime.MemProfileRate = 0
	}

	log.Logf(0, "dialing manager at %v", *flagManager)
	manager, err := rpctype.NewRPCClient(*flagManager)
	if err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}
	log.Logf(1, "connecting to manager...")
	a := &rpctype.ConnectArgs{Name: *flagName}
	r := &rpctype.ConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		log.Fatalf("failed to connect to manager: %v ", err)
	}
	featureFlags, err := csource.ParseFeaturesFlags("none", "none", true)
	if err != nil {
		log.Fatal(err)
	}
	if r.CheckResult == nil {
		checkArgs.gitRevision = r.GitRevision
		checkArgs.targetRevision = r.TargetRevision
		checkArgs.enabledCalls = r.EnabledCalls
		checkArgs.allSandboxes = r.AllSandboxes
		checkArgs.featureFlags = featureFlags
		r.CheckResult, err = checkMachine(checkArgs)
		if err != nil {
			if r.CheckResult == nil {
				r.CheckResult = new(rpctype.CheckArgs)
			}
			r.CheckResult.Error = err.Error()
		}
		r.CheckResult.Name = *flagName
		if err := manager.Call("Manager.Check", r.CheckResult, nil); err != nil {
			log.Fatalf("Manager.Check call failed: %v", err)
		}
		if r.CheckResult.Error != "" {
			log.Fatalf("%v", r.CheckResult.Error)
		}
	} else {
		if err = host.Setup(target, r.CheckResult.Features, featureFlags, config.Executor); err != nil {
			log.Fatal(err)
		}
	}

	// zip new data from manager
	if len(r.ProgSeed) > 0 {
		log.Logf(0, "Received seed prog\n")
	}

	log.Logf(0, "syscalls: %v", len(r.CheckResult.EnabledCalls[sandbox]))
	for _, feat := range r.CheckResult.Features.Supported() {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}
	createIPCConfig(r.CheckResult.Features, config)

	if *flagRunTest {
		runTest(target, manager, *flagName, config.Executor)
		return
	}

	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}

	fuzzer := &Fuzzer{
		name:                     *flagName,
		outputType:               outputType,
		config:                   config,
		execOpts:                 execOpts,
		workQueue:                newWorkQueue(*flagProcs, needPoll),
		needPoll:                 needPoll,
		manager:                  manager,
		target:                   target,
		faultInjectionEnabled:    r.CheckResult.Features[host.FeatureFault].Enabled,
		comparisonTracingEnabled: r.CheckResult.Features[host.FeatureComparisons].Enabled,
		corpusHashes:             make(map[hash.Sig]struct{}),
		spliceEnabled:            r.SpliceEnabled,
		corpusSyscall:            make(map[string]bool),
	}
	gateCallback := fuzzer.useBugFrames(r, *flagProcs)
	fuzzer.gate = ipc.NewGate(2**flagProcs, gateCallback)

	for i := 0; fuzzer.poll(i == 0, nil); i++ {
	}
	calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
	}
	/*
			type ExecOpts struct {
			Flags     ExecFlags
			FaultCall int // call index for fault injection (0-based)
			FaultNth  int // fault n-th operation in the call (0-based)
		}
	*/
	p, fault, faultCall, faultNth := fuzzer.deserializeInput(r.ProgSeed)
	if fault != false && faultCall != -1 && faultNth != -1 {
		fuzzer.execOpts.FaultCall = faultCall
		fuzzer.execOpts.FaultNth = faultNth
		fuzzer.execOpts.Flags |= 1 << 2
	}
	if p == nil {
		log.Logf(0, "Failed to deserialize the seed poc")
	} else {
		fuzzer.workQueue.enqueue(&WorkSeed{
			p: p,
		})
		log.Logf(0, "Added seed prog\n")

		// make sure the syscalls in the poc are enabled
		for _, c := range p.Calls {
			calls[c.Meta] = true
		}
	}

	fuzzer.choiceTable = target.BuildChoiceTable(fuzzer.corpus, calls)

	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzer, pid)
		if err != nil {
			log.Fatalf("failed to create proc: %v", err)
		}
		//changed by yuhang
		proc.fuzzer.Counter = 0
		proc.fuzzer.Ctrlnum = 0

		fuzzer.procs = append(fuzzer.procs, proc)
		go proc.loop()
	}

	fuzzer.pollLoop()
}

// Returns gateCallback for leak checking if enabled.
func (fuzzer *Fuzzer) useBugFrames(r *rpctype.ConnectRes, flagProcs int) func() {
	var gateCallback func()

	if r.CheckResult.Features[host.FeatureLeak].Enabled {
		gateCallback = func() { fuzzer.gateCallback(r.MemoryLeakFrames) }
	}

	if r.CheckResult.Features[host.FeatureKCSAN].Enabled && len(r.DataRaceFrames) != 0 {
		fuzzer.filterDataRaceFrames(r.DataRaceFrames)
	}

	return gateCallback
}

func (fuzzer *Fuzzer) gateCallback(leakFrames []string) {
	// Leak checking is very slow so we don't do it while triaging the corpus
	// (otherwise it takes infinity). When we have presumably triaged the corpus
	// (triagedCandidates == 1), we run leak checking bug ignore the result
	// to flush any previous leaks. After that (triagedCandidates == 2)
	// we do actual leak checking and report leaks.
	triagedCandidates := atomic.LoadUint32(&fuzzer.triagedCandidates)
	if triagedCandidates == 0 {
		return
	}
	args := append([]string{"leak"}, leakFrames...)
	output, err := osutil.RunCmd(10*time.Minute, "", fuzzer.config.Executor, args...)
	if err != nil && triagedCandidates == 2 {
		// If we exit right away, dying executors will dump lots of garbage to console.
		os.Stdout.Write(output)
		fmt.Printf("BUG: leak checking failed")
		time.Sleep(time.Hour)
		os.Exit(1)
	}
	if triagedCandidates == 1 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 2)
	}
}

func (fuzzer *Fuzzer) filterDataRaceFrames(frames []string) {
	args := append([]string{"setup_kcsan_filterlist"}, frames...)
	output, err := osutil.RunCmd(10*time.Minute, "", fuzzer.config.Executor, args...)
	if err != nil {
		log.Fatalf("failed to set KCSAN filterlist: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (fuzzer *Fuzzer) pollLoop() {
	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second).C
	for {
		poll := false
		select {
		case <-ticker:
		case <-fuzzer.needPoll:
			poll = true
		}
		if fuzzer.outputType != OutputStdout && time.Since(lastPrint) > 10*time.Second {
			// Keep-alive for manager.
			log.Logf(0, "alive, executed %v", execTotal)
			log.Logf(0, "size of corpus %v, size of corpusSyscall", len(fuzzer.corpus), len(fuzzer.corpusSyscall))
			lastPrint = time.Now()
		}
		if poll || time.Since(lastPoll) > 10*time.Second {
			needCandidates := fuzzer.workQueue.wantCandidates()
			if poll && !needCandidates {
				continue
			}
			stats := make(map[string]uint64)
			for _, proc := range fuzzer.procs {
				stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
				stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
			}
			for stat := Stat(0); stat < StatCount; stat++ {
				v := atomic.SwapUint64(&fuzzer.stats[stat], 0)
				stats[statNames[stat]] = v
				execTotal += v
			}
			if !fuzzer.poll(needCandidates, stats) {
				lastPoll = time.Now()
			}
		}
	}
}

func (fuzzer *Fuzzer) poll(needCandidates bool, stats map[string]uint64) bool {
	a := &rpctype.PollArgs{
		Name:           fuzzer.name,
		NeedCandidates: needCandidates,
		MaxSignal:      fuzzer.grabNewSignal().Serialize(),
		Stats:          stats,
	}
	r := &rpctype.PollRes{}
	if err := fuzzer.manager.Call("Manager.Poll", a, r); err != nil {
		log.Fatalf("Manager.Poll call failed: %v", err)
	}
	maxSignal := r.MaxSignal.Deserialize()
	log.Logf(0, "poll: candidates=%v inputs=%v signal=%v",
		len(r.Candidates), len(r.NewInputs), maxSignal.Len())
	fuzzer.addMaxSignal(maxSignal)
	for _, inp := range r.NewInputs {
		fuzzer.addInputFromAnotherFuzzer(inp)
	}
	for _, candidate := range r.Candidates {
		fuzzer.addCandidateInput(candidate)
	}
	if needCandidates && len(r.Candidates) == 0 && atomic.LoadUint32(&fuzzer.triagedCandidates) == 0 {
		atomic.StoreUint32(&fuzzer.triagedCandidates, 1)
	}
	return len(r.NewInputs) != 0 || len(r.Candidates) != 0 || maxSignal.Len() != 0
}
func (fuzzer *Fuzzer) syncReltoManager(CallIdx int, ArgIdx int, P []byte) {
	a := &rpctype.SyncRelationArgs{
		CallIdx: CallIdx,
		ArgIdx:  ArgIdx,
		P:       P,
	}
	if err := fuzzer.manager.Call("Manager.SyncRelation", a, nil); err != nil {
		log.Fatalf("syc relationship call failed: %v", err)
	}
}
func (fuzzer *Fuzzer) getRelation() (int, int, []byte) {
	a := &rpctype.SyncRelationArgs{}
	b := &rpctype.GetRelRes{}
	if err := fuzzer.manager.Call("Manager.GetRelation", a, b); err != nil {
		log.Fatalf("get relationship call failed: %v", err)
	}
	cid := b.CallIdx
	aid := b.ArgIdx
	poc := b.Poc
	return cid, aid, poc
}
func (fuzzer *Fuzzer) syncRelationBuildingSeed(P []byte) {
	a := &rpctype.SyncRelationArgs{
		CallIdx: 0,
		ArgIdx:  0,
		P:       P,
	}
	if err := fuzzer.manager.Call("Manager.SyncRelationBuildingSeed", a, nil); err != nil {
		log.Fatalf("SyncRelationBuildingSeed call failed: %v", err)
	}
}

func (fuzzer *Fuzzer) getRelationBuildingSig() (bool, []byte) {
	a := &rpctype.SyncRelationArgs{}
	b := &rpctype.GetRelRes{}
	if err := fuzzer.manager.Call("Manager.GetRelationBuildingSig", a, b); err != nil {
		log.Fatalf("GetRelationBuildingSig call failed: %v", err)
	}
	cid := b.CallIdx
	aid := b.ArgIdx
	poc := b.Poc
	if cid == -1 && aid == -1 {
		return true, poc
	} else {
		return false, poc
	}
}

func (fuzzer *Fuzzer) sendInputToManager(inp rpctype.RPCInput) {
	a := &rpctype.NewInputArgs{
		Name:     fuzzer.name,
		RPCInput: inp,
	}
	if err := fuzzer.manager.Call("Manager.NewInput", a, nil); err != nil {
		log.Fatalf("Manager.NewInput call failed: %v", err)
	}
}

func (fuzzer *Fuzzer) addInputFromAnotherFuzzer(inp rpctype.RPCInput) {
	// FIXME: add lock here
	// sync the corpus syscall among the fuzzers
	fuzzer.corpusSyscall[inp.Call] = true

	p, fault, faultCall, faultNth := fuzzer.deserializeInput(inp.Prog)
	if fault != false && faultCall != -1 && faultNth != -1 {
		fuzzer.execOpts.FaultCall = faultCall
		fuzzer.execOpts.FaultNth = faultNth
		fuzzer.execOpts.Flags |= 1 << 2
	}
	if p == nil {
		return
	}
	sig := hash.Hash(inp.Prog)
	sign := inp.Signal.Deserialize()
	// TO-DO-y
	objSig := inp.ObjSig.Deserialize()
	TraceSig := inp.TraceSig.Deserialize()
	PatchSig := inp.PatchSig.Deserialize()
	if PatchSig != nil {
		fuzzer.patchAddInputToCorpus(p, PatchSig, sig)
	} else {
		fuzzer.addInputToCorpus(p, sign, objSig, TraceSig, sig)
	}
}

func (fuzzer *Fuzzer) addCandidateInput(candidate rpctype.RPCCandidate) {
	p, _, _, _ := fuzzer.deserializeInput(candidate.Prog)
	if p == nil {
		return
	}
	flags := ProgCandidate
	if candidate.Minimized {
		flags |= ProgMinimized
	}
	if candidate.Smashed {
		flags |= ProgSmashed
	}
	fuzzer.workQueue.enqueue(&WorkCandidate{
		p:     p,
		flags: flags,
	})
}

func (fuzzer *Fuzzer) deserializeInput(inp []byte) (*prog.Prog, bool, int, int) {
	p, err := fuzzer.target.Deserialize(inp, prog.NonStrict)
	fault := false
	faultCall := -1
	faultNth := -1

	if err != nil {
		ents := fuzzer.target.ParseLog(inp)
		for _, ee := range ents {
			p = ee.P
			fault = ee.Fault
			faultCall = ee.FaultCall
			faultNth = ee.FaultNth

		}
	}

	if p == nil {
		log.Fatalf("failed to deserialize prog: %v\n%s", err, inp)
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil, false, -1, -1
	}
	return p, fault, faultCall, faultNth
}

func (fuzzer *FuzzerSnapshot) chooseProgram(r *rand.Rand) *prog.Prog {
	randVal := r.Int63n(fuzzer.sumPrios + 1)
	idx := sort.Search(len(fuzzer.corpusPrios), func(i int) bool {
		return fuzzer.corpusPrios[i] >= randVal
	})
	return fuzzer.corpus[idx]
}

func (fuzzer *Fuzzer) enableCorpusSyscall(p *prog.Prog) {
	for _, call := range p.Calls {
		fuzzer.corpusSyscall[call.Meta.Name] = true
	}
}

func (fuzzer *Fuzzer) addInputToCorpus(p *prog.Prog, sign signal.Signal, objSig signal.Signal, traceSig signal.Signal, sig hash.Sig) {
	fuzzer.corpusMu.Lock()
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		fuzzer.corpus = append(fuzzer.corpus, p)
		fuzzer.corpusHashes[sig] = struct{}{}
		prio := int64(len(sign))
		if sign.Empty() {
			prio = 1
		}
		fuzzer.sumPrios += prio
		fuzzer.corpusPrios = append(fuzzer.corpusPrios, fuzzer.sumPrios)

		fuzzer.enableCorpusSyscall(p)

		fuzzer.corpusMu.Unlock()
		tmpCorpus := fuzzer.snapshot().corpus
		fuzzer.corpusMu.Lock()
		if len(fuzzer.corpusSyscall) > 1 && len(tmpCorpus) > 0 {
			fuzzer.corpusChoiceTable = fuzzer.target.BuildCorpusChoiceTable(tmpCorpus, fuzzer.corpusSyscall)
		}
	}
	fuzzer.corpusMu.Unlock()

	if !sign.Empty() || !objSig.Empty() || !traceSig.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSignal.Merge(sign)
		fuzzer.corpusObjSignal.Merge(objSig)
		fuzzer.corpusTraceSignal.Merge(traceSig)
		fuzzer.maxSignal.Merge(sign)
		fuzzer.maxObjSignal.Merge(objSig)
		fuzzer.maxTraceSignal.Merge(traceSig)
		fuzzer.signalMu.Unlock()
	}
}

//yuhang
func (fuzzer *Fuzzer) patchAddInputToCorpus(p *prog.Prog, sign signal.PatchSig, sig hash.Sig) {
	fuzzer.corpusMu.Lock()
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		fuzzer.corpus = append(fuzzer.corpus, p)
		fuzzer.corpusHashes[sig] = struct{}{}
		prio := int64(len(sign))
		if sign.Empty() {
			prio = 1
		}
		fuzzer.sumPrios += prio
		fuzzer.corpusPrios = append(fuzzer.corpusPrios, fuzzer.sumPrios)

		fuzzer.enableCorpusSyscall(p)

		fuzzer.corpusMu.Unlock()
		tmpCorpus := fuzzer.snapshot().corpus
		fuzzer.corpusMu.Lock()
		if len(fuzzer.corpusSyscall) > 1 && len(tmpCorpus) > 0 {
			fuzzer.corpusChoiceTable = fuzzer.target.BuildCorpusChoiceTable(tmpCorpus, fuzzer.corpusSyscall)
		}
	}
	//fuzzer.enableCorpusSyscall(p)
	fuzzer.corpusMu.Unlock()

	if !sign.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusPatchSignal.Merge(sign)
		fuzzer.maxPatchSignal.Merge(sign)
		fuzzer.signalMu.Unlock()
	}
}

func (fuzzer *Fuzzer) snapshot() FuzzerSnapshot {
	fuzzer.corpusMu.RLock()
	defer fuzzer.corpusMu.RUnlock()
	return FuzzerSnapshot{fuzzer.corpus, fuzzer.corpusPrios, fuzzer.sumPrios}
}

func (fuzzer *Fuzzer) addMaxSignal(sign signal.Signal) {
	if sign.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSignal.Merge(sign)
}

func (fuzzer *Fuzzer) grabNewSignal() signal.Signal {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	sign := fuzzer.newSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newSignal = nil
	return sign
}

// yuhang set relationship between args and var
func (fuzzer *Fuzzer) setRel(info *ipc.ProgInfo, callandargs []map[int]int) int {
	// init fuzzer.variableHashesRes
	res := 0
	if fuzzer.variableHashesRes == nil {
		fuzzer.variableHashesRes = make(map[uint32][]map[int]int)
	}
	if fuzzer.variableHashes == nil {
		fuzzer.variableHashes = make(map[uint32]map[uint64]bool)
	}
	//tmp_var := false
	//log.Logf(0, "setRel, hashvar map len %lx", info.Calls)
	for i := range info.Calls {
		log.Logf(0, "hashvar %d", info.Calls[i].Hashvar)
		//if len(info.Calls[i].Hashvar) > 0 {
		//	tmp_var = true
		//}
		for j := range info.Calls[i].Hashvar {
			//panic("signal!")
			//first 32 bit is the hash value, last 32 bits are the index
			index := uint32(info.Calls[i].HashvarIdx[j])
			hash_value := uint64(info.Calls[i].Hashvar[j])
			log.Logf(0, "index: %lx, hash_value: %lx", index, hash_value)
			// judge if index is the key of fuzzer.variableHashes
			if _, ok := fuzzer.variableHashes[index]; ok {
				log.Logf(0, "\n\n*****variableHasheslist: %v *****\n\n", fuzzer.variableHashes)
				// judge if the hash_value is the key of fuzzer.variableHashes[index]
				if v, ok := fuzzer.variableHashes[index][hash_value]; ok && v == true {
					fuzzer.variableHashes[index][hash_value] = true
				} else {

					// set fuzzer.variableHashes[index][hash_value] = true
					fuzzer.variableHashes[index][hash_value] = true
					fuzzer.variableHashesRes[index] = callandargs
					res = 1
					//panic("bbbbbbb")
					//fuzzer.variableHashesRes[index] = false
				}
			} else {
				// set fuzzer.variableHashes[index][hash_value] = true
				fuzzer.variableHashes[index] = make(map[uint64]bool)
				fuzzer.variableHashes[index][hash_value] = true
				//res = 1
				//fuzzer.variableHashesRes[index] = false
			}

		}
	}
	//if tmp_var {
	return res
	//} else {
	//	return -1
	//}
}

func (fuzzer *Fuzzer) corpusSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSignal.Diff(sign)
}

func (fuzzer *Fuzzer) corpusObjSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusObjSignal.Diff(sign)
}

func (fuzzer *Fuzzer) corpusPatchSignalDiff(sign signal.PatchSig) signal.PatchSig {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusPatchSignal.Diff(sign)
}

func (fuzzer *Fuzzer) corpusTraceSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusTraceSignal.Diff(sign)
}

func (fuzzer *Fuzzer) checkNewSignal(p *prog.Prog, info *ipc.ProgInfo) (calls []int, extra bool) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	for i, inf := range info.Calls {
		if fuzzer.checkNewCallSignal(p, &inf, i) {
			calls = append(calls, i)
		}
	}
	extra = fuzzer.checkNewCallSignal(p, &info.Extra, -1)
	return
}

func (fuzzer *Fuzzer) getObjSignal(p *prog.Prog, info *ipc.ProgInfo, call int) signal.Signal {
	inf := &info.Calls[call]
	prio := signalPrio(p, inf, call)
	return signal.ObjCovFromRaw(inf.ObjCover, prio)
}

func (fuzzer *Fuzzer) getTraceSignal(p *prog.Prog, info *ipc.ProgInfo, call int) signal.Signal {
	inf := &info.Calls[call]
	prio := signalPrio(p, inf, call)
	return signal.TraceFromRaw(inf.PreTrace, inf.EnableTrace, inf.PostTrace, prio)
}

func (fuzzer *Fuzzer) getPatchSignal(p *prog.Prog, info *ipc.ProgInfo, call int) signal.PatchSig {
	inf := &info.Calls[call]
	prio := signalPrio(p, inf, call)
	return signal.PatchFuzzerFromRaw(inf.Similarity, inf.HashvarIdx, inf.Hashvar, prio)
}

func (fuzzer *Fuzzer) getAllObjSignal(p *prog.Prog, info *ipc.ProgInfo) signal.Signal {
	var prio uint8
	var objSig signal.Signal
	for i := range info.Calls {
		prio = signalPrio(p, &info.Calls[i], i)
		objSig.Merge(signal.ObjCovFromRaw(info.Calls[i].ObjCover, prio))
	}
	return objSig
}

func (fuzzer *Fuzzer) checkNewObjSignal(p *prog.Prog, info *ipc.ProgInfo) (calls []int, extra bool) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	// objSig := fuzzer.getObjSignal(p, info)

	// newObjSig := fuzzer.maxObjSignal.Diff(objSig)
	// if newObjSig.Empty() {
	// 	return false
	// }

	for i, inf := range info.Calls {
		if fuzzer.checkNewObjCallSignal(p, &inf, i) {
			calls = append(calls, i)
		}
	}
	// extra = fuzzer.checkNewObjCallSignal(p, &inf, i)
	extra = false
	return
}

func (fuzzer *Fuzzer) checkNewTraceSignal(p *prog.Prog, info *ipc.ProgInfo) (calls []int, extra bool) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()

	for i, inf := range info.Calls {
		if fuzzer.checkNewTraceCallSignal(p, &inf, i) {
			calls = append(calls, i)
		}
	}
	extra = false
	return
}

func (fuzzer *Fuzzer) checkNewPatchSignal(p *prog.Prog, info *ipc.ProgInfo) (calls []int, extra bool) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()

	for i, inf := range info.Calls {
		if fuzzer.checkNewPatchCallSignal(p, &inf, i) {
			calls = append(calls, i)
		}
	}
	extra = false
	return
}

func (fuzzer *Fuzzer) getObjCoverSize(info *ipc.ProgInfo) int {
	size := 0
	for i := range info.Calls {
		size += len(info.Calls[i].ObjCover)
	}
	return size
}

func (fuzzer *Fuzzer) getTraceSize(info *ipc.ProgInfo) int {
	size := 0
	for i := range info.Calls {
		size += len(info.Calls[i].EnableTrace)
		size += len(info.Calls[i].PreTrace)
		size += len(info.Calls[i].ObjCover)
		size += len(info.Calls[i].Hashvar)
	}
	return size
}

func (fuzzer *Fuzzer) checkNewCallSignal(p *prog.Prog, info *ipc.CallInfo, call int) bool {
	diff := fuzzer.maxSignal.DiffRaw(info.Signal, signalPrio(p, info, call))
	if diff.Empty() {
		return false
	}
	fuzzer.signalMu.RUnlock()
	fuzzer.signalMu.Lock()
	fuzzer.maxSignal.Merge(diff)
	fuzzer.newSignal.Merge(diff)
	fuzzer.signalMu.Unlock()
	fuzzer.signalMu.RLock()
	return true
}

func (fuzzer *Fuzzer) checkNewObjCallSignal(p *prog.Prog, info *ipc.CallInfo, call int) bool {
	// diff := fuzzer.maxSignal.DiffRaw(info.Signal, signalPrio(p, info, call))
	objSig := signal.ObjCovFromRaw(info.ObjCover, signalPrio(p, info, call))
	diff := fuzzer.maxObjSignal.Diff(objSig)

	if diff.Empty() {
		return false
	}
	fuzzer.signalMu.RUnlock()
	fuzzer.signalMu.Lock()
	fuzzer.maxSignal.Merge(diff)
	fuzzer.maxObjSignal.Merge(diff)
	fuzzer.newObjSignal.Merge(diff)
	fuzzer.newSignal.Merge(diff)
	fuzzer.signalMu.Unlock()
	fuzzer.signalMu.RLock()
	return true
}

func (fuzzer *Fuzzer) checkNewTraceCallSignal(p *prog.Prog, info *ipc.CallInfo, call int) bool {
	// diff := fuzzer.maxSignal.DiffRaw(info.Signal, signalPrio(p, info, call))
	traceSig := signal.TraceFromRaw(info.PreTrace, info.EnableTrace, info.PostTrace, signalPrio(p, info, call))
	diff := fuzzer.maxTraceSignal.Diff(traceSig)

	if diff.Empty() {
		return false
	}
	fuzzer.signalMu.RUnlock()
	fuzzer.signalMu.Lock()
	fuzzer.maxTraceSignal.Merge(diff)
	fuzzer.maxSignal.Merge(diff)
	fuzzer.newTraceSignal.Merge(diff)
	fuzzer.newSignal.Merge(diff)
	fuzzer.signalMu.Unlock()
	fuzzer.signalMu.RLock()
	return true
}

func (fuzzer *Fuzzer) checkNewPatchCallSignal(p *prog.Prog, info *ipc.CallInfo, call int) bool {
	// diff := fuzzer.maxSignal.DiffRaw(info.Signal, signalPrio(p, info, call))
	PatchSig := signal.PatchFuzzerFromRaw(info.Similarity, info.HashvarIdx, info.Hashvar, signalPrio(p, info, call))
	diff := fuzzer.maxPatchSignal.Diff(PatchSig)
	if diff.Empty() {
		return false
	}
	fuzzer.signalMu.RUnlock()
	fuzzer.signalMu.Lock()
	fuzzer.maxPatchSignal.Merge(diff)
	fuzzer.newPatchSignal.Merge(diff)
	fuzzer.signalMu.Unlock()
	fuzzer.signalMu.RLock()
	return true
}

func (fuzzer *Fuzzer) getPatchFuzzerSig(p *prog.Prog, info *ipc.CallInfo, call int) signal.PatchSig {
	prio := signalPrio(p, info, call)
	return signal.PatchFuzzerFromRaw(info.Similarity, info.HashvarIdx, info.Hashvar, prio)
}

func signalPrio(p *prog.Prog, info *ipc.CallInfo, call int) (prio uint8) {
	if call == -1 {
		return 0
	}
	if info.Errno == 0 {
		prio |= 1 << 1
	}
	if !p.Target.CallContainsAny(p.Calls[call]) {
		prio |= 1 << 0
	}
	return
}

func parseOutputType(str string) OutputType {
	switch str {
	case "none":
		return OutputNone
	case "stdout":
		return OutputStdout
	case "dmesg":
		return OutputDmesg
	case "file":
		return OutputFile
	default:
		log.Fatalf("-output flag must be one of none/stdout/dmesg/file")
		return OutputNone
	}
}
