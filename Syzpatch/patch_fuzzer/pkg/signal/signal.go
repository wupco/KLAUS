// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package signal provides types for working with feedback signal.
package signal

type (
	elemType uint32
	prioType int8
)

type Signal map[elemType]prioType
type PatchSig map[uint32]map[uint64]uint32
type Serial struct {
	Elems []elemType
	Prios []prioType
}

type PatchSerial struct {
	PSig map[uint32]map[uint64]uint32
	//Elems []elemType
	//Prios []prioType
}

func (s Signal) Len() int {
	return len(s)
}

func (s PatchSig) Len() int {
	return len(s)
}

func (s Signal) Empty() bool {
	return len(s) == 0
}

func (s PatchSig) Empty() bool {
	return len(s) == 0
}

func (s Signal) Copy() Signal {
	c := make(Signal, len(s))
	for e, p := range s {
		c[e] = p
	}
	return c
}

func (s *Signal) Split(n int) Signal {
	if s.Empty() {
		return nil
	}
	c := make(Signal, n)
	for e, p := range *s {
		delete(*s, e)
		c[e] = p
		n--
		if n == 0 {
			break
		}
	}
	if len(*s) == 0 {
		*s = nil
	}
	return c
}

func FromRaw(raw []uint32, prio uint8) Signal {
	if len(raw) == 0 {
		return nil
	}
	s := make(Signal, len(raw))
	for _, e := range raw {
		s[elemType(e)] = prioType(prio)
	}
	return s
}

func PatchFuzzerFromRaw(Similarity []uint64, HashvarIdx []uint32, Hashvar []uint64, prio uint8) PatchSig {
	if len(Hashvar) == 0 || len(HashvarIdx) == 0 || len(Hashvar) != len(HashvarIdx) {
		return nil
	}
	//total_sim := 0
	//for i := range Similarity {
	//	total_sim += int(Similarity[i])
	//}

	variableHashesRes := make(PatchSig)
	//go through HashvarIdx and Hashvar using the minimum max index of HashvarIdx and Hashvar

	for i := range HashvarIdx {
		index := HashvarIdx[i]
		hash_value := Hashvar[i]
		_, ok := variableHashesRes[index][hash_value]
		if !ok {
			variableHashesRes[index] = make(map[uint64]uint32)
		}
		variableHashesRes[index][hash_value] = uint32(prio)
	}

	//calc_prio := (1 + total_sim) * (1 + total_static_var)

	return variableHashesRes

}
func TraceFromRaw(PreTrace []uint32, EnableTrace []uint32, PostTrace []uint32, prio uint8) Signal {
	if len(PreTrace) == 0 && len(EnableTrace) == 0 {
		return nil
	}
	s := make(Signal, len(PreTrace)+len(EnableTrace))
	for _, e := range EnableTrace {
		if val, ok := s[elemType(e)]; ok {
			if (val >> 4) < 0x4 {
				s[elemType(e)] = prioType(val + (2 << 4))
			}
		} else {
			s[elemType(e)] = prioType(prio)
		}
	}
	for _, e := range PostTrace {
		if val, ok := s[elemType(e)]; ok {
			if (val >> 4) < 0x4 {
				s[elemType(e)] = prioType(val + (1 << 4))
			}
		} else {
			continue
		}
	}
	for _, e := range PreTrace {
		if val, ok := s[elemType(e)]; ok {
			if (val >> 4) < 0x4 {
				s[elemType(e)] = prioType(val + (1 << 4))
			}
		} else {
			s[elemType(e)] = prioType(prio)
		}
	}
	return s
}

func ObjCovFromRaw(raw []uint32, prio uint8) Signal {
	if len(raw) == 0 {
		return nil
	}
	s := make(Signal, len(raw))
	for _, e := range raw {
		if val, ok := s[elemType(e)]; ok {
			// higher signal value when the same object address
			// is covered. we use 5th bit to 7th from the last since it's
			// unused in signalPrio, signalPrio uses the last and
			// second from the last.
			if (val >> 4) < 0x4 { // 4 is the max value
				s[elemType(e)] = prioType(val + (1 << 4))
			}
		} else {
			s[elemType(e)] = prioType(prio)
		}
	}
	return s
}

func (s Signal) Serialize() Serial {
	if s.Empty() {
		return Serial{}
	}
	res := Serial{
		Elems: make([]elemType, len(s)),
		Prios: make([]prioType, len(s)),
	}
	i := 0
	for e, p := range s {
		res.Elems[i] = e
		res.Prios[i] = p
		i++
	}
	return res
}

func (s PatchSig) Serialize() PatchSerial {
	//map[uint32]map[uint32]uint32
	if s.Empty() {
		return PatchSerial{}
	}
	res := PatchSerial{
		PSig: s,
	}
	return res
}

func (ser Serial) Deserialize() Signal {
	if len(ser.Elems) != len(ser.Prios) {
		panic("corrupted Serial")
	}
	if len(ser.Elems) == 0 {
		return nil
	}
	s := make(Signal, len(ser.Elems))
	for i, e := range ser.Elems {
		s[e] = ser.Prios[i]
	}
	return s
}

func (ser PatchSerial) Deserialize() PatchSig {
	//map[uint32]map[uint32]uint32
	if len(ser.PSig) == 0 {
		return nil
	}
	s := ser.PSig
	return s
}

func (s Signal) Diff(s1 Signal) Signal {
	if s1.Empty() {
		return nil
	}
	var res Signal
	for e, p1 := range s1 {
		if p, ok := s[e]; ok && p >= p1 {
			continue
		}
		if res == nil {
			res = make(Signal)
		}
		res[e] = p1
	}
	return res
}
func (s PatchSig) Diff(s1 PatchSig) PatchSig {
	//panic("\ntest1:\n")

	if s1.Empty() {
		return nil
	}
	//panic("\ntest0\n")
	var res PatchSig
	for e, p1 := range s1 {
		for e2, p2 := range p1 {
			// judge if s[e] exists and s[e][e2] exists
			if _, ok := s[e]; ok {
				if p, ok := s[e][e2]; ok && p >= p2 {
					continue
				}
				if res == nil {
					res = make(PatchSig)
				}
				if _, ok := res[e][e2]; !ok {
					res[e] = make(map[uint64]uint32)
				}
				res[e][e2] = p2
			} else {
				res = make(PatchSig)
				res[e] = make(map[uint64]uint32)
				res[e][e2] = p2
			}
		}
	}
	return res
}
func (s Signal) DiffRaw(raw []uint32, prio uint8) Signal {
	var res Signal
	for _, e := range raw {
		if p, ok := s[elemType(e)]; ok && p >= prioType(prio) {
			continue
		}
		if res == nil {
			res = make(Signal)
		}
		res[elemType(e)] = prioType(prio)
	}
	return res
}

func (s Signal) Intersection(s1 Signal) Signal {
	if s1.Empty() {
		return nil
	}
	res := make(Signal, len(s))
	for e, p := range s {
		if p1, ok := s1[e]; ok && p1 >= p {
			res[e] = p
		}
	}
	return res
}

func (s PatchSig) Intersection(s1 PatchSig) PatchSig {
	if s1.Empty() {
		return nil
	}
	res := make(PatchSig)
	for e, p0 := range s {
		for e2, p := range p0 {
			if _, ok := s1[e]; ok {
				if p1, ok := s1[e][e2]; ok && p1 >= p {
					if _, ok := res[e][e2]; !ok {
						res[e] = make(map[uint64]uint32)
					}
					res[e][e2] = p
				}
			}
		}
	}
	return res
}

func (s *Signal) Merge(s1 Signal) {
	if s1.Empty() {
		return
	}
	s0 := *s
	if s0 == nil {
		s0 = make(Signal, len(s1))
		*s = s0
	}
	for e, p1 := range s1 {
		if p, ok := s0[e]; !ok || p < p1 {
			s0[e] = p1
		}
	}
}

func (s *PatchSig) Merge(s1 PatchSig) {
	if s1.Empty() {
		return
	}
	s0 := *s
	if s0 == nil {
		s0 = make(PatchSig)
		*s = s0
	}
	//|| p < p1
	for e, p2 := range s1 {
		for e1, p1 := range p2 {
			if _, ok := s0[e]; !ok {
				//set s0[e][e1] = p1
				s0[e] = make(map[uint64]uint32)
				s0[e][e1] = p1
			} else {
				if p, ok := s0[e][e1]; !ok || p < p1 {
					s0[e][e1] = p1
				}
			}
		}
	}
}

type Context struct {
	Signal  Signal
	Context interface{}
}

func Minimize(corpus []Context) []interface{} {
	type ContextPrio struct {
		prio prioType
		idx  int
	}
	covered := make(map[elemType]ContextPrio)
	for i, inp := range corpus {
		for e, p := range inp.Signal {
			if prev, ok := covered[e]; !ok || p > prev.prio {
				covered[e] = ContextPrio{
					prio: p,
					idx:  i,
				}
			}
		}
	}
	indices := make(map[int]struct{}, len(corpus))
	for _, cp := range covered {
		indices[cp.idx] = struct{}{}
	}
	result := make([]interface{}, 0, len(indices))
	for idx := range indices {
		result = append(result, corpus[idx].Context)
	}
	return result
}
