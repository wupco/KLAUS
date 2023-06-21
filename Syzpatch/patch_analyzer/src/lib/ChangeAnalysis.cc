#include <llvm/ADT/StringExtras.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/TypeFinder.h>
#include <llvm/Pass.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>

#include "ChangeAnalysis.h"
#include "llvm-diff/DifferenceEngine.h"

#include <deque>

#define WHOLE_FUNC_ANALYZE

extern cl::opt<unsigned> DisableLLVMDiff;

using namespace llvm;
using namespace std;

// try to express v using var in vars
Value *ChangeAnalysisPass::resolveValue(Value *v, ValueSet vars) {
  return v;
  if (vars.find(v) != vars.end())
    return v;

  if (!isa<Instruction>(v)) {
    KA_WARNS(0, *v << "is not a instruction");
    return v;
  }

  Instruction *I = cast<Instruction>(v);
  KA_LOGS(2, "resloving instruction " << *I);
  switch (I->getOpcode()) {
  case Instruction::PHI:
  case Instruction::Call:
  case Instruction::Load:
    // resolve the loaded value as the address of loading
    return resolveValue(I->getOperand(0), vars);

  case Instruction::GetElementPtr:
    KA_WARNS(0, "Unknown GEI " << *I);
    return v;
  default:
    break;
  }

  if (I->isUnaryOp() || I->isBinaryOp() || I->isCast()) {
    Instruction *newI = I->clone();
    for (int i = 0; i < I->getNumOperands(); i++) {
      newI->setOperand(i, resolveValue(newI->getOperand(i), vars));
    }
    KA_LOGS(0, "old inst " << *I);
    KA_LOGS(0, "got a new inst " << *newI);
    return newI;
  }

  KA_WARNS(0, "handle " << *I);
  assert(0);
}

StringRef ChangeAnalysisPass::handleType(Type *ty) {

  if (ty == nullptr)
    return StringRef("");

    // debug type
#if 0
    std::string type_str;
    llvm::raw_string_ostream rso(type_str);
    ty->print(rso);
    KA_LOGS(0, "type :" << rso.str());
#endif

  if (ty->isStructTy()) {
    StructType *ST = dyn_cast<StructType>(ty);
    StringRef stname = ST->getName();

    // substitude
    if (stname.startswith("struct.") && !stname.startswith("struct.anon")) {
      return stname.split("struct.").second.split(".").first;
    }
    return "";

  } else if (ty->isPointerTy()) {
    ty = cast<PointerType>(ty)->getElementType();
    return handleType(ty);
  } else if (ty->isArrayTy()) {
    ty = cast<ArrayType>(ty)->getElementType();
    return handleType(ty);
  } else if (ty->isIntegerTy()) {
    return StringRef("int");
  }

  return StringRef("");
}

// resolve value to a unique, comparable string
string ChangeAnalysisPass::strValue(Value *v, ValueSet vars) {
  // if it is a GEI, return object+offset
  // if it is a dbgvar, return it's name
  // if it is a call, return function name
  // others: value op value
  if (v == nullptr)
    return "";
  if (!isa<Instruction>(v)) {
    if (auto constInt = dyn_cast<ConstantInt>(v)) {
      return std::to_string(constInt->getZExtValue());
    }
    return "";
  }

  if (DbgMap.find(v) != DbgMap.end()) {
    auto dbgInst = DbgMap[v];
    // TODO: extract variable name from the dbgInst
  }

  // remove CastInst
  while (isa<CastInst>(v)) {
    auto CI = cast<CastInst>(v);
    v = CI->getOperand(0);
  }

  if (!isa<Instruction>(v)) {
    if (auto constInt = dyn_cast<ConstantInt>(v)) {
      return std::to_string(constInt->getZExtValue());
    }
    return "";
  }

  Instruction *I = cast<Instruction>(v);
  // KA_LOGS(1, "op name " << I->getOpcodeName());
  // KA_LOGS(1, "Instruction " << *I);
  switch (I->getOpcode()) {
  // case Instruction::PHI:
  case Instruction::Call: {
    Function *F = cast<CallInst>(I)->getCalledFunction();
    if (!F || (F && !F->hasName()))
      return "noName";
    return F->getName().str();
  }
  case Instruction::Load:
    // resolve the loaded value as the address of loading
    return strValue(I->getOperand(0), vars);

  case Instruction::GetElementPtr: {
    GetElementPtrInst *GEI = cast<GetElementPtrInst>(I);
    auto name = handleType(GEI->getSourceElementType()).str();
    if (name.find(".", 7) != string::npos) {
      name = name.substr(0, name.find(".", 7));
    }

    if (StructType *st = dyn_cast<StructType>(GEI->getSourceElementType())) {
      if (auto ci = dyn_cast<ConstantInt>(
              GEI->getOperand(GEI->getNumOperands() - 1))) {
        Module *M = I->getParent()->getModule();
        DataLayout DL = M->getDataLayout();
        const StructLayout *sl = DL.getStructLayout(st);
        uint64_t offset = sl->getElementOffset((unsigned)ci->getZExtValue());
      }
    }

    for (unsigned i = 1; i < GEI->getNumOperands(); i++) {
      if (auto constInt = dyn_cast<ConstantInt>(GEI->getOperand(i))) {
        name += ".";
        name += std::to_string(constInt->getZExtValue());
      }
    }
    KA_LOGS(1, "got " << StringRef(name) << " From GEI");
    return name;
  }
  case Instruction::ICmp: {
    // TODO
    // KA_LOGS(0, "Got icmp inst " << *I);
    auto ICMP = cast<ICmpInst>(I);
    auto name = ICMP->getPredicateName(ICMP->getPredicate()).str();
    for (unsigned i = 0; i < ICMP->getNumOperands(); i++) {
      name += " " + strValue(ICMP->getOperand(i), vars);
    }
    KA_LOGS(1, "Got str for ICMP " << name);
    return name;
  }
  // avoid potential path explosion
  case Instruction::PHI: {
    auto name = std::string(I->getOpcodeName()) + " ";
    for (int i = 0; i < I->getNumOperands(); i++) {
      name += " " + std::to_string(i);
    }
    return name;
  }
  default:
    break;
  }

  if (I->isUnaryOp() || I->isBinaryOp()) {
    auto name = std::string(I->getOpcodeName()) + " ";
    for (int i = 0; i < I->getNumOperands(); i++) {
      name += " " + strValue(I->getOperand(i), vars);
    }
    KA_LOGS(1, "got unique name from OP : " << name);
    return name;
  }

  KA_WARNS(1, "instruction has no name");

  auto name = std::string(I->getOpcodeName()) + " ";
  for (int i = 0; i < I->getNumOperands(); i++) {
    name += " " + strValue(I->getOperand(i), vars);
  }
  // KA_LOGS(0, "got unique name from OP : " << name);
  return name;
}

CondNode ChangeAnalysisPass::getCond(BasicBlockPair pair, ValueSet vars) {
  Value *cond = nullptr;
  bool trueBranch = false;

  if (!pair.first)
    return std::make_pair(cond, trueBranch);
  if (auto brI = dyn_cast<BranchInst>(pair.first->getTerminator())) {
    if (brI->isConditional()) {
      cond = brI->getCondition();
      if (brI->getSuccessor(0) == pair.second) {
        trueBranch = true;
      }
    }
  }

  if (cond) {
    KA_LOGS(1, "get a cond " << *cond);
    // cond = resolveValue(cond, vars);
  }

  return std::make_pair(cond, trueBranch);
}

bool ChangeAnalysisPass::isSameCondNode(CondNode cNodeA, CondNode cNodeB) {
  if (cNodeA.first == cNodeB.first) {
    if (cNodeA.second == cNodeB.second)
      return true;
  }
  return false;
}

bool ChangeAnalysisPass::isSameCond(Cond condA, Cond condB) {
  if (condA.size() != condB.size()) {
    return false;
  }

  for (unsigned i = 0; i < condA.size(); i++) {
    if (!isSameCondNode(condA[i], condB[i])) {
      return false;
    }
    // if (!containCondNode(condB, condA[i])) {
    //   return false;
    // }
  }
  return true;
}

bool ChangeAnalysisPass::containCondNode(Cond cond, CondNode condNode) {
  // if the condNode is null, means no condition, should return true
  if (condNode.first == nullptr)
    return true;

  for (auto cNode : cond) {
    if (isSameCondNode(cNode, condNode)) {
      return true;
    }
  }
  return false;
}

// contain same condNode but different satisfication
int ChangeAnalysisPass::containCondNodeBranch(Cond cond, CondNode condNode) {
  if (condNode.first == nullptr)
    return -1;
  int idx = 0;
  for (auto cNode : cond) {
    if (cNode.first == condNode.first && cNode.second != condNode.second) {
      return idx;
    }
    idx++;
  }
  return -1;
}

int ChangeAnalysisPass::findCondNode(Cond cond, CondNode condNode) {
  if (condNode.first == nullptr)
    return -1;
  int idx = 0;
  for (auto cNode : cond) {
    if (cNode.first == condNode.first) {
      return idx;
    }
    idx++;
  }
  return -1;
}

// remove condNode with the same vars
bool ChangeAnalysisPass::sanitizeCond(Cond &cond, CondNode condNode) {
  // return false;
  int idx = findCondNode(cond, condNode);
  if (idx != -1) {
    KA_LOGS(1, "removing node " << *condNode.first);
    cond.erase(cond.begin() + idx);
    return true;
  }
  return false;
}

// add pre cond for the set of value
bool ChangeAnalysisPass::addCond(GenSet &GS, CondNode condNode) {
  bool added = false;
  for (auto element : GS) {
    for (auto condVal : element.second) {
      if (!containCondNode(condVal.first, condNode)) {
        condVal.first.push_back(condNode);
        added = true;
      }
    }
  }
  return added;
}

// union two sets with a condition
// add setB to setA
// cond in condNode might be nullptr
void ChangeAnalysisPass::unionSet(GenSet &setA, GenSet setB,
                                  CondNode condNode) {
  for (auto element : setB) {
    if (setA.find(element.first) != setA.end()) {
      setA[element.first].insert(setB[element.first].begin(),
                                 setB[element.first].end());
    } else {
      setA[element.first] = setB[element.first];
    }
  }

  addCond(setA, condNode);
}

// add setB to setA
bool ChangeAnalysisPass::unionSet(GenSet &setA, GenSet setB) {
  bool changed = false;
  for (auto element : setB) {
    if (setA.find(element.first) != setA.end()) {
      // auto res = setA[element.first].insert(setB[element.first].begin(),
      //                                       setB[element.first].end());
      // changed |= res.second;
      for (auto eleB : setB[element.first]) {
        changed |= setA[element.first].insert(eleB).second;
      }
    } else {
      setA[element.first] = setB[element.first];
      changed |= true;
    }
  }
  return changed;
}

bool ChangeAnalysisPass::unionCondSet(CondSet &setA, CondSet setB) {
  bool ret = false;
  for (auto condB : setB) {
    bool found = false;
    for (auto condA : setA) {
      if (isSameCond(condA, condB)) {
        found = true;
        break;
      }
    }

    if (!found) {
      // KA_LOGS(0, "got new condition:");
      setA.insert(condB);
      ret = true;
    }
  }
  return ret;
}

// recursive function finding a fixed point
// <value, cond> should be unique, unless add it
// and return changed
bool ChangeAnalysisPass::analyzeBasicBlock(
    BasicBlock *b,
    /* variable we care about */ ValueSet vars,
    CondSet preCondSet, /*pre-cond to reach this block*/
    /* */ std::map<Value *, std::set<CondVal>> &defInfo,
    /* */ std::map<Value *, std::set<CondVal>> &useInfo) {

  // CondNode condNode = getCond(BP);
  // // the state under this condition has been handled,
  // // just return it without changes.
  // // FIXME
  // if (cond.find(condNode) == cond.end()) {
  //   return false;
  // }

  // // add the condition of this state
  // cond.push_back(condNode);

  KA_LOGS(1, "analyzing basic block : " << *b);
  bool changed = false;

  for (auto &i : *b) {
    Instruction *I = &i;
    if (isa<LoadInst>(I)) {
      // if (isa<LoadInst>(I) || (isa<CallInst>(I))) {
      Value *use;
      if (auto LI = dyn_cast<LoadInst>(I)) {
        use = resolveValue(LI->getOperand(0), vars);
      } else {
        Function *F = cast<CallInst>(I)->getCalledFunction();
        if (F && F->hasName() && F->getName().startswith("llvm."))
          continue;
        use = cast<Value>(I);
      }

      if (isa<AllocaInst>(use))
        continue;

      if (useInfo.find(use) == useInfo.end()) {
        // find precondition of use: cond/trueBranch
        std::set<CondVal> condValSet;
        for (auto preCond : preCondSet) {
          condValSet.insert(std::make_pair(preCond, nullptr));
        }
        loadMap[use] = I;
        useInfo[use] = condValSet;
        changed = true;

        KA_LOGS(1, "found a new use site" << *use << ", condition:");
        // dump(condValSet);
      } else {
        // check if preCond is in the cond set
        // if it is, no need to update
        // if not, insert a pair with all conditions
        auto condValSet = useInfo[use];
        bool exist = false;
        for (auto condVal : condValSet) {
          for (auto preCond : preCondSet)
            if (!isSameCond(condVal.first, preCond)) {
              condValSet.insert(std::make_pair(preCond, nullptr));
              changed = true;
            }
        }
        if (changed) {
          KA_LOGS(1, "found a seen use site" << *use << ", condition:");
          // dump(condValSet);
        }
      }
    } else if (isa<StoreInst>(I) || isa<CallInst>(I)) {
      Value *stVal, *stAddr;
      if (auto SI = dyn_cast<StoreInst>(I)) {
        stVal = SI->getOperand(0);
        stAddr = SI->getOperand(1);
      } else {
        Function *F = cast<CallInst>(I)->getCalledFunction();
        if (!F || !F->hasName() || F->getName().startswith("llvm."))
          continue;
        auto FName = F->getName().str();
        if (isupper(FName[0]))
          continue;

        stAddr = cast<Value>(I);
        stVal = nullptr;
      }

      if (isa<AllocaInst>(stAddr))
        continue;

      stVal = resolveValue(stVal, vars);
      stAddr = resolveValue(stAddr, vars);

      if (defInfo.find(stAddr) == defInfo.end()) {
        storeMap[stAddr] = I;
        std::set<CondVal> condValSet;
        // condVal.first = preCond;
        // condVal.second = stVal;
        // condValSet.insert(condVal);
        for (auto preCond : preCondSet) {
          condValSet.insert(std::make_pair(preCond, stVal));
        }
        defInfo[stAddr] = condValSet;
        KA_LOGS(1, "store inst " << *I);
        KA_LOGS(1, "found a new store site " << *stAddr << ", condition:");
        // dump(condValSet);
      } else {
        auto condValSet = defInfo[stAddr];
        bool exist = false;
        for (auto condVal : condValSet) {
          if (condVal.second == stVal) {
            for (auto preCond : preCondSet) {
              if (!isSameCond(condVal.first, preCond)) {
                condValSet.insert(std::make_pair(preCond, stVal));
                changed = true;
              }
            }
            exist = true;
          }
        }

        if (!exist) {
          // no such value in the set
          for (auto preCond : preCondSet) {
            condValSet.insert(std::make_pair(preCond, stVal));
            changed = true;
          }
        }

        if (changed) {
          KA_LOGS(1, "found a seen store site" << *stAddr << ", condition:");
          // dump(condValSet);
        }
      }
    } else {
      // if I is the value of our interest
    }
  }
  return changed;
}

// this function is also used in analyzing whole function
// input a start and end point of basic block
// return the variables of possible value with constraints.
// the set of value are represented as variables identified last step
GenSetPair ChangeAnalysisPass::analyzeValueSetRange(BasicBlockPair pair,
                                                    ValueSet vars) {
  // new use:
  // 1. a new global variable
  // 2. same variable, new possible value
  // new/dead def
  // 1. value set of each variable
  BasicBlock *start = pair.first;
  BasicBlock *end = pair.second;

  KA_LOGS(0, "start block : " << *start);
  KA_LOGS(0, "end block : " << *end);

  std::vector<Value *> useVec;
  std::vector<Value *> defVec;

  // cond: vector cond1, cond2
  // {addr : (<cond, val>, <cond, val>)}
  // typedef std::pair<Value*, bool> CondNode;
  // typedef std::vector<CondNode> Cond;
  // typedef std::pair<Cond, Value*> CondVal;
  // typedef std::map<Value*, std::set<CondVal>> GenSet;

  std::map<Value *, std::set<CondVal>> defInfo;
  std::map<Value *, std::set<CondVal>> useInfo;

  // #if 0
  //   std::deque<BasicBlockPair> changeSet;
  //   bool changed = true;
  //   changeSet.push_back(std::make_pair<nullptr, start>);
  //   while (changed) {
  //     changed = false;
  //     for (auto bp : changeSet) {
  //       if (bp.second == end) continue;
  //       for (auto *succ : successors(bp.second)) {
  //         if (!std::find(changeSet.begin(), changeSet.end(),
  //               std::make_pair(bp.second, succ))) {
  //           changeSet.push_back(std::make_pair(bp.second, succ));
  //           changed = true;
  //         }
  //       }
  //     }
  //   }
  // #endif

  std::deque<BasicBlock *> changeSet;
  bool changed = true;
  bool condChanged = true;
  changeSet.push_back(start);
  while (changed) {
    changed = false;
    for (auto b : changeSet) {
      if (b == end)
        continue;
      for (auto *succ : successors(b)) {
        if (std::find(changeSet.begin(), changeSet.end(), succ) ==
            changeSet.end()) {
          changeSet.push_back(succ);
          changed = true;
        }
      }
    }
  }

  KA_LOGS(0, "size of changeset " << changeSet.size());

  // current block and pre block
  std::map<BasicBlock *, std::pair<GenSet, GenSet>> blockEntry;
  std::map<BasicBlock *, std::pair<GenSet, GenSet>> blockExit;

  std::map<BasicBlock *, std::set<Cond>> blockCondEntry;
  std::map<BasicBlock *, std::set<Cond>> blockCondExit;

  std::set<CondNode> loggedCondNode;

  while (!changeSet.empty()) {
    BasicBlock *current = changeSet.front();
    changeSet.pop_front();
    changed = false;
    condChanged = false;

    // init block entry if it is not
    if (blockEntry.find(current) == blockEntry.end()) {
      GenSet blockUseInfo;
      GenSet blockDefInfo;
      blockEntry[current] = std::make_pair(blockDefInfo, blockUseInfo);
    }

    if (blockExit.find(current) == blockExit.end()) {
      GenSet blockUseInfo;
      GenSet blockDefInfo;
      blockExit[current] = std::make_pair(blockDefInfo, blockUseInfo);
    }

    if (blockCondEntry.find(current) == blockCondEntry.end()) {
      std::set<Cond> condSet;
      Cond cond;
      // only the dominator worth init condition
      // otherwise it will generate a lot duplicated conditions
      if (current == start) {
        cond.push_back(std::make_pair(nullptr, 0));
        condSet.insert(cond);
      }
      blockCondEntry[current] = condSet;
    }

    if (blockCondExit.find(current) == blockCondExit.end()) {
      blockCondExit[current] = blockCondEntry[current];
    }

    // find predecessors
#if 0
    // if (current != start) {
    //   for (auto *pre : predecessors(current)) {
    //     if (blockExit.find(pre) != blockExit.end()) {
    //       // union the result
    //       auto preCondNode = getCond(std::make_pair(pre, current), vars);
    //       // could be a conditional jump
    //       // could not be a conditional jump

    //       // should check if this condNode is already in the entry
    //       auto preCondSet = blockCondExit[pre];
    //       std::set<Cond> newCurCondSet;

    //       for (auto preCond : preCondSet) {
    //         // make a copy???
    //         Cond curCond(preCond);
    //         if (!containCondNode(curCond, preCondNode)) {
    //           curCond.push_back(preCondNode);
    //         }
    //         newCurCondSet.insert(curCond);
    //       }
    //       // KA_LOGS(0, "dumping conditions, size "<<newCurCondSet.size());
    //       // dump(newCurCondSet);

    //       // union new curCondSet
    //       // FIXME shoud union two sets
    //       // unionCondSet(blockCondEntry[current], newCurCondSet);
    //       // update block exit accordingly
    //       blockCondExit[current] = blockCondEntry[current];

    //       unionSet(blockEntry[current].first, blockExit[pre].first);
    //       unionSet(blockEntry[current].second, blockExit[pre].second);

    //       // make a copy of block entry
    //       GenSet entryDefInfo(blockEntry[current].first);
    //       GenSet entryUseInfo(blockEntry[current].second);

    //       // KA_LOGS(0, "before analysis");
    //       // dump(entryDefInfo);
    //       // dump(entryUseInfo);
    //       analyzeBasicBlock(current, vars, newCurCondSet, entryDefInfo,
    //                         entryUseInfo);
    //       // unionSet(blockEntry[current].first, blockExit[pre].first,
    //       // tmpCondNode); unionSet(blockEntry[current].second,
    //       // blockExit[pre].second, tmpCondNode);

    //       // KA_LOGS(0, "after analysis");
    //       // dump(entryDefInfo);
    //       // dump(entryUseInfo);

    //       changed |= unionSet(blockExit[current].first, entryDefInfo);
    //       changed |= unionSet(blockExit[current].second, entryUseInfo);
    //       // KA_LOGS(0, "after union");
    //       // dump(blockExit[current].first);
    //       // dump(blockExit[current].second);
    //     }
    //   }
    // } else {
    //   // no predecessor
    //   GenSet entryDefInfo;
    //   GenSet entryUseInfo;
    //   CondSet pre;
    //   changed |=
    //       analyzeBasicBlock(current, vars, pre, entryDefInfo, entryUseInfo);

    //   unionSet(blockExit[current].first, entryDefInfo);
    //   unionSet(blockExit[current].second, entryUseInfo);
    // }
#else
    if (current != start) {
      // condition set to reach current block
      blockCondEntry[current].clear();
      for (auto *pre : predecessors(current)) {
        if (blockExit.find(pre) != blockExit.end()) {
          // union the result
          auto preCondNode = getCond(std::make_pair(pre, current), vars);
          if (preCondNode.first && loggedCondNode.insert(preCondNode).second) {
            KA_LOGS(0, "adding condNode " << *preCondNode.first
                                          << preCondNode.second);
          }
          // could be a conditional jump
          // could not be a conditional jump

          // should check if this condNode is already in the entry
          auto preCondSet = blockCondExit[pre];
          std::set<Cond> newCurCondSet;

          // 1. sanitizer the preCondSet itself
          for (auto preCond : preCondSet) {
            if (preCond.size() == 0) {
              // precond is not initialized, skip this
              // otherwise we will see a lot ofduplicated
              // conditions
              continue;
            }
            // make a copy???
            // do a sanitization here, remove redudent cond
            Cond curCond(preCond);
            if (containCondNodeBranch(curCond, preCondNode) != -1) {
              // it is contradict, then it is a merge point
              // merge them!
              sanitizeCond(curCond, preCondNode);
            } else {
              // avoid redudent condNode
              if (!containCondNode(curCond, preCondNode)) {
                curCond.push_back(preCondNode);
              }
            }

            newCurCondSet.insert(curCond);
          }

          // 2. sanitizer the preCondSet with each other
          // TODO
          for (auto cond : newCurCondSet) {
          }

          // KA_LOGS(0, "dumping conditions, size "<<newCurCondSet.size());
          // dump(newCurCondSet);

          // union new curCondSet
          unionCondSet(blockCondEntry[current], newCurCondSet);

          unionSet(blockEntry[current].first, blockExit[pre].first);
          unionSet(blockEntry[current].second, blockExit[pre].second);
        } else {
          // predecessor is not ready, skip this block
          // KA_WARNS(0, "predecessor is not initialized : " << *pre);
          continue;
        }
      }

      // do a sanitizer, remove redudent cond in blockCondEntry, merge
      // conditions

      // merge point: when adding a new cond, if the reverse of new condNode
      // exists in all the cond, then this is the merge point
      // do the merge operation here

      // KA_LOGS(0, "dumping cond set ");
      // for (auto condSet : blockCondEntry[current]) {
      //   dump(condSet);
      // }
      KA_LOGS(2, "block cond set size " << blockCondEntry[current].size());
      KA_LOGS(2, "block  " << *current);
      if (blockCondEntry[current].size() > 1) {
        auto baseCond = *std::next(blockCondEntry[current].begin(), 1);
        std::set<CondNode> removeNodeSet;
        std::set<Cond> replaceCondSet;
        removeNodeSet.clear();
        for (auto condNode : baseCond) {
          for (auto cond : blockCondEntry[current]) {
            if (cond == baseCond)
              continue;
            if (containCondNodeBranch(cond, condNode) != -1) {
              removeNodeSet.insert(condNode);
              // replaceCondSet.insert(cond);
              KA_LOGS(0, "We found a merge point!");
              KA_LOGS(0, *condNode.first << " : " << condNode.second);
              // dump(cond);
              KA_LOGS(2, "Done");
              break;
            }
          }
        }

        if (removeNodeSet.size() > 0) {
          KA_LOGS(0, "remove set size " << removeNodeSet.size());
          // step 1: remove the duplicated cond
          // replaceCondSet.insert(baseCond);
          std::set<Cond> condSet = blockCondEntry[current];
          for (auto cc : condSet) {
            Cond cond(cc);
            bool sanitized = false;
            for (auto condNode : removeNodeSet) {
              if (sanitizeCond(cond, condNode)) {
                sanitized |= true;
              }
            }
            if (sanitized) {
              // replace
              KA_LOGS(2, "replacing the cond");
              assert(blockCondEntry[current].find(cc) !=
                     blockCondEntry[current].end());
              blockCondEntry[current].erase(blockCondEntry[current].find(cc));
              bool found = false;
              for (auto rCond : blockCondEntry[current]) {
                if (isSameCond(cond, rCond)) {
                  found = true;
                  KA_WARNS(1, "Found a already existing cond!!!");
                }
              }
              if (!found) {
                KA_LOGS(2, "inserting cond ");
                // dump(cond);
                blockCondEntry[current].insert(cond);
                condChanged |= true;
              }
            }
          }
        }

        // for (auto condSet : blockCondEntry[current]) {
        //   KA_LOGS(0, "after sanitizing, cond set ");
        //   dump(condSet);
        // }
      }

      // KA_LOGS(0, "block " << *current);
      // dump(blockCondEntry[current]);
      // KA_LOGS(0, "Done");

      // update block exit accordingly
      blockCondExit[current] = blockCondEntry[current];

      // make a copy of block entry
      GenSet oldDefInfo(blockExit[current].first);
      GenSet oldUseInfo(blockExit[current].second);

      // only do the analysis if the precond is new
      // or the block has not been analyzed before
      // hacky here: the exit set is empty means no
      // analysis before

      // FIXED: analyzing basic block is not heavy,
      // analyze it anyway
      // if (condChanged || oldDefInfo.empty() || oldUseInfo.empty()) {
      analyzeBasicBlock(current, vars, blockCondEntry[current], oldDefInfo,
                        oldUseInfo);
      // }
      // unionSet(blockEntry[current].first, blockExit[pre].first,
      // tmpCondNode); unionSet(blockEntry[current].second,
      // blockExit[pre].second, tmpCondNode);

      changed |= unionSet(blockExit[current].first, oldDefInfo);
      changed |= unionSet(blockExit[current].second, oldUseInfo);
      changed |= unionSet(blockExit[current].first, blockEntry[current].first);
      changed |=
          unionSet(blockExit[current].second, blockEntry[current].second);

      if (changed) {
        KA_LOGS(1, "changed");
      }
    } else {
      // this is the starting basic block
      // no predecessor
      GenSet entryDefInfo;
      GenSet entryUseInfo;
      CondSet pre;
      KA_LOGS(0, "analyzing the start block\n");
      analyzeBasicBlock(current, vars, pre, entryDefInfo, entryUseInfo);
      changed = true;

      unionSet(blockExit[current].first, entryDefInfo);
      unionSet(blockExit[current].second, entryUseInfo);
    }
#endif

    changed |= condChanged;

    if (changed && current != end) {
      for (auto *succ : successors(current)) {
        if (std::find(changeSet.begin(), changeSet.end(), succ) ==
            changeSet.end()) {
          changeSet.push_back(succ);
        }
      }
    }
  }

  // we should return the result of value set at the "end" block
  assert(blockExit.find(end) != blockExit.end() && "Found nothing at the end");
  return blockExit[end];
}

// find first bitcast and return
static User *removeBCI(User *I) {
  if (!isa<BitCastInst>(I))
    return I;

  for (auto user : cast<Instruction>(I)->users()) {
    if (isa<BitCastInst>(user)) {
      return removeBCI(user);
    } else {
      return user;
    }
  }
  return I;
}

// TODO: need an alias analysis
// find out variables associated with args
// like arg1->field ----> GEI op

// the following variable will be cared:
// 1. var containing a name
// 2. GEP and Load/Store pair

// this function figures out which variable we are care about
// we will asign a unique name for variable we identified
// return a map {name : (var)}
std::set<Value *> ChangeAnalysisPass::findVariables(Function *func) {
  KA_LOGS(1, "\nfinding variables in " << func->getName() << "\n");

  std::set<Value *> resVars;

  // alias analysis
  legacy::FunctionPassManager *FPM =
      new legacy::FunctionPassManager(func->getParent());
  AAResultsWrapperPass *AA = new AAResultsWrapperPass();
  FPM->add(AA);
  FPM->run(*func);
  AAResults &AAR = AA->getAAResults();

  if (aliasMap.find(func) == aliasMap.end()) {
    aliasMap[func] = &AAR;
  }

  // collect variables
  std::set<Value *> vars;
  for (auto &arg : func->args()) {
    // all args are interesting
    resVars.insert(&arg);
    if (arg.getType()->isPointerTy())
      vars.insert(&arg);
  }
  for (Instruction &I : instructions(*func)) {
    if (I.getType()->isPointerTy())
      vars.insert(&I);
  }

  std::vector<llvm::DbgValueInst *> dbgValueVec;
  std::set<Value *> dbgVars;
  for (auto &inst : instructions(*func)) {
    Instruction *I = &inst;
    if (auto *dbgV = dyn_cast<DbgValueInst>(I)) {
      dbgValueVec.push_back(dbgV);
      dbgVars.insert(dbgV->getVariableLocation());
      // all debug variables are interesting.
      resVars.insert(dbgV->getVariableLocation());

      // store the debug information
      if (DbgMap.find(dbgV->getVariableLocation()) != DbgMap.end()) {
        KA_LOGS(1, "old " << *DbgMap[dbgV->getVariableLocation()]);
        KA_LOGS(1, "new " << *dbgV);
        // assert(DbgMap[dbgV->getVariableLocation()] == dbgV);
      }
      DbgMap[dbgV->getVariableLocation()] = cast<Value>(dbgV);

      // outs() << "Found dbg value " << *dbgV << "\n";
      // outs() << "variable : " << *dbgV->getVariableLocation() << "\n";
      // outs() << "DIvariable : " << *dbgV->getVariable() << "\n";
    }

    if (isa<GetElementPtrInst>(I)) {
      bool validGEI = false;
      for (auto *user_ : I->users()) {
        User *user = removeBCI(user_);
        // check if it is valid
        if (isa<CallInst>(user) || isa<LoadInst>(user) ||
            isa<StoreInst>(user)) {
          validGEI = true;
          break;
        }
      }

      if (validGEI)
        resVars.insert(I);
      else
        KA_WARNS(0, "not a typical GEI : " << *I);
    }

    if (isa<CallInst>(I)) {
      for (unsigned i = 0; i < I->getNumOperands(); i++) {
        resVars.insert(I->getOperand(i));
      }
    }
  }

  KA_LOGS(1, "size of resVars " << resVars.size());
  for (auto v : resVars) {
    KA_LOGS(1, "var : " << *v);
  }
  return resVars;

#if 0
  // find alias of debug variables
  std::map<Value*, Value*> aliasMap;
  for (auto var1 : dbgVars) {
    if (!var1->getType()->isPointerTy()) continue;

    for (auto var2 : vars) {
      if (var1 == var2) {
        continue
      }
      AliasResult AResult = AAR.alias(var1, var2);

      if (AResult == MushAlias || AResult == PartialAlias) {
        // FIXME: might kill sth
        aliasMap[var2] = var1;
      }
    }
  }

  for (auto var : aliasMap) {
    for (auto *user : var->users()) {
      if (isa<GetElementPtrInst>(user)) {
        // set a unique name for this
        resVars.insert(user);
      }
    }
  }

  // look for GEP Load/Store pattern.
  std::set<Value *> LoadVars;
  std::set<Value *> StoreVars;
  for (auto &inst : instructions(*func)) {
    Instruction *I = &inst;
    if (auto *LI = dyn_cast<LoadInst>(I)) {
      // LoadVars.insert(I);
      LoadVars.insert(LI->getOperand(0)) // if find a load to it, it is a use
    } else if (auto *SI = dyn_cast<StoreInst>(I)) {
      StoreVars.insert(SI->getOperand(0)); // find a store to it, it is a define
      // StoreVars.insert(SI->getOperand(1));
    }
  }
#endif
}

// analyze the whole function
BasicBlockPair ChangeAnalysisPass::findRange(BasicBlock *b) {
  Function *Func = b->getParent();
  KA_LOGS(0, "Doing analysis on " << Func->getName());

  BasicBlock *Entry = &Func->getEntryBlock();
  assert(Entry == &Func->front());
  BasicBlock *Exit = &Func->back();

#ifdef WHOLE_FUNC_ANALYZE

  return std::make_pair(Entry, Exit);

#else
  // DominatorTree and PostDominatorTree for patched function
  auto *PDTPass = new PostDominatorTreeWrapperPass();
  PDTPass->runOnFunction(*Func);
  PDTPass->verifyAnalysis();
  auto PDT = &PDTPass->getPostDomTree();

  auto *DTPass = new DominatorTreeWrapperPass();
  DTPass->runOnFunction(*Func);
  DTPass->verifyAnalysis();
  auto DT = &DTPass->getDomTree();

  BasicBlock *PDTBB = nullptr;
  BasicBlock *DTBB = nullptr;

  if (&Func->front() == b) {
    DTBB = b;
  }

  if (&Func->back() == b) {
    PDTBB = b;
  }

  for (auto &BB : Func->getBasicBlockList()) {
    if (&BB == b)
      continue;
    if (!PDTBB && PDT->dominates(BB.getTerminator(), b->getTerminator())) {
      PDTBB = &BB;
    }
    if (DT->dominates(&BB.front(), b->getTerminator())) {
      DTBB = &BB;
    }
  }

  // assert(DTBB && PDTBB);
  // KA_LOGS(0, "Found dominator at " << *DTBB);
  // KA_LOGS(0, "Found postdominator at " << *PDTBB);

  return std::make_pair(DTBB, PDTBB);
  // return std::make_pair(b, PDTBB);
#endif
}

bool ChangeAnalysisPass::condNodeMatch(CondNode condNodeA, CondNode condNodeB) {
  if (strValue(condNodeA.first, rawVars) ==
      strValue(condNodeB.first, patchedVars)) {
    if (condNodeA.second == condNodeB.second) {
      return true;
    }
  }
  return false;
}

bool ChangeAnalysisPass::condMatch(Cond condA, Cond condB) {
  if (condA.size() == condB.size()) {
    for (unsigned i = 0; i < condA.size(); i++) {
      if (!condNodeMatch(condA[i], condB[i]))
        return false;
    }
    return true;
  }
  return false;
}

bool ChangeAnalysisPass::condValMatch(CondVal condValA, CondVal condValB) {
  if (strValue(condValA.second, rawVars) ==
      strValue(condValB.second, patchedVars)) {
    if (condMatch(condValA.first, condValB.first)) {
      // KA_LOGS(0, "Found a match ");
      // // KA_LOGS(0, *condValA.first);
      // dump(condValA.first);
      // KA_LOGS(0, "matches");
      // dump(condValB.first);
      // KA_LOGS(0, *condValB.first);
      return true;
    }
  }
  return false;
}

bool ChangeAnalysisPass::containCondNode(Cond cond, CondNode condNode,
                                         std::set<Value *> condAVar,
                                         std::set<Value *> condBVar) {
  for (auto cNode : cond) {
    if (strValue(cNode.first, condAVar) == strValue(condNode.first, condBVar)) {
      if (cNode.second == condNode.second) {
        return true;
      }
    }
  }
  return false;
}

// generate a cond that A is satisfied, but B is unsatisfied
Cond ChangeAnalysisPass::reverseCond(Cond condA, Cond condB,
                                     std::set<Value *> condAVar,
                                     std::set<Value *> condBVar) {
  // KA_LOGS(0, "in reverseCond, condA");
  // dump(condA);
  // KA_LOGS(0, "condB");
  // dump(condB);
  // KA_LOGS(0, "Done");
  Cond out;
  // step 1: make sure B is a subset of A
  // so, all cond in A can be found in B
  for (auto nodeA : condA) {
    if (!containCondNode(condB, nodeA, condAVar, condBVar)) {
      return out;
    }
  }
  if (condA.size() == condB.size()) {
    // A and B are the same
    return out;
  }

  for (auto nodeB : condB) {
    if (!containCondNode(condA, nodeB, condAVar, condBVar)) {
      // do a negation
      CondNode neg(nodeB);
      neg.second = ~neg.second;
      KA_LOGS(1, "reverseCond: got a cute cond: " << *neg.first << " "
                                                  << neg.second);
      out.push_back(neg);
    }
  }
  return out;
}

static void genSetInsert(GenSet &GS, Value *key, CondVal condVal) {
  if (GS.find(key) != GS.end()) {
    GS[key].insert(condVal);
  } else {
    std::set<CondVal> condValSet;
    condValSet.insert(condVal);
    GS[key] = condValSet;
  }
}

void ChangeAnalysisPass::compareValues(GenSetPair raw, GenSetPair patched) {
  // compare def set
  // new def: stores exist in patched, not found in raw
  // dead def: stores exist in raw, not found in patched
  // uew use: load exist in patched, not found in raw
  // the following code is ugly
  // std::set<CondVal> newDef, deadDef, newUse;

  // dead def
  for (auto ele : raw.first) {
    auto curVarName = strValue(ele.first, rawVars);
    bool exist = false;
    for (auto elePatched : patched.first) {
      if (curVarName == strValue(elePatched.first, patchedVars)) {
        // A: <addr1 : {<cond1,>, val1}>
        // B: <addr1 : {<cond1, cond2>, val1}>
        exist = true;
        for (auto condValRaw : ele.second) {
          bool condValExist = false;
          CondVal condVal;
          unsigned minCondSize = -1;
          // make sure the condVal exists
          for (auto condValPatched : elePatched.second) {
            if (condValExist)
              break;
            if (strValue(condValRaw.second, rawVars) ==
                strValue(condValPatched.second, patchedVars)) {
              auto cond = reverseCond(condValRaw.first, condValPatched.first,
                                      rawVars, patchedVars);
              if (cond.size()) {
                if (cond.size() < minCondSize) {
                  condVal.first = cond; // FIXME: this cond is from raw
                  condVal.second = condValPatched.second;
                  minCondSize = cond.size();
                }
              } else {
                condValExist = true;
              }
            }
          }

          if (condValExist == false) {
            genSetInsert(deadDef, elePatched.first, condVal);
          }
        }
      }
    }

    if (!exist) {
      // not exist in patched set
      // raw: <addr, {<cond>, val}>
      // patched: <empty>

      KA_LOGS(1, "Found a dead def");
      KA_LOGS(1, "addr " << *ele.first);
      if (ele.second.size() == 0) {
        CondVal condVal;
        genSetInsert(deadDef, ele.first, condVal);
      } else {
        for (auto condValRaw : ele.second)
          genSetInsert(deadDef, ele.first, condValRaw);
      }
    }
  }

  // new def: stores exist in patched, not found in raw
  for (auto elePatched : patched.first) {
    auto curVarName = strValue(elePatched.first, patchedVars);
    bool exist = false;
    for (auto eleRaw : raw.first) {
      if (curVarName == strValue(eleRaw.first, rawVars)) {
        exist = true;
        // compare condNode
        // cond in patched should all exist in raw
        // otherwise, it is a new def
        for (auto condValPatched : elePatched.second) {
          bool condValExist = false;
          CondVal condVal;
          unsigned minCondSize = -1;
          // make sure the condVal exists
          for (auto condValRaw : eleRaw.second) {
            if (condValExist)
              break;
            if (strValue(condValRaw.second, rawVars) ==
                strValue(condValPatched.second, patchedVars)) {
              // check if cond are partial matched
              auto cond = reverseCond(condValPatched.first, condValRaw.first,
                                      patchedVars, rawVars);
              if (cond.size()) {
                if (cond.size() < minCondSize) {
                  condVal.first = cond;
                  condVal.second = condValPatched.second;
                  minCondSize = cond.size();
                }
              } else {
                condValExist = true;
              }
            }
          }

          if (condValExist == false) {
            genSetInsert(newDef, elePatched.first, condVal);
          }
        }
      }
    }

    if (!exist) {
      // not exist in raw set
      KA_LOGS(1, "Found a new def");
      KA_LOGS(1, "addr " << *elePatched.first);
      if (elePatched.second.size() == 0) {
        CondVal condVal;
        genSetInsert(newDef, elePatched.first, condVal);
      } else {
        for (auto condVal : elePatched.second)
          genSetInsert(newDef, elePatched.first, condVal);
      }
    }
  }

  // new use: load exist in patched, not found in raw
  for (auto elePatched : patched.second) {
    auto curVarName = strValue(elePatched.first, patchedVars);
    bool exist = false;
    for (auto eleRaw : raw.second) {
      if (curVarName == strValue(eleRaw.first, rawVars)) {
        exist = true;
        // compare condNode
        // cond in patched should all exist in raw
        // otherwise, it is a new use
        for (auto condValPatched : elePatched.second) {
          bool condValExist = false;
          CondVal condVal;
          unsigned minCondSize = -1;
          // make sure the condVal exists
          for (auto condValRaw : eleRaw.second) {
            if (condValExist)
              break;
            auto cond = reverseCond(condValPatched.first, condValRaw.first,
                                    patchedVars, rawVars);
            if (cond.size()) {
              if (cond.size() < minCondSize) {
                condVal.first = cond;
                minCondSize = cond.size();
              }
            } else {
              condValExist = true;
            }
          }
        }
      }
    }

    if (!exist) {
      // not exist in patched set

      KA_LOGS(1, "Found a new use");
      KA_LOGS(1, "addr " << *elePatched.first);
      if (elePatched.second.size() == 0) {
        CondVal condVal;
        genSetInsert(newUse, elePatched.first, condVal);
      } else {
        for (auto condVal : elePatched.second)
          genSetInsert(newUse, elePatched.first, condVal);
      }
    }
  }

  KA_LOGS(0, "dumping new def");
  dump(newDef);
  KA_LOGS(0, "---------------------------------");
  KA_LOGS(0, "dumping dead def");
  dump(deadDef);
  KA_LOGS(0, "---------------------------------");
  KA_LOGS(0, "dumping new use");
  dump(newUse);
}

string ChangeAnalysisPass::findIntraRepresentation(Value *v) {
  // backward until we found that it is from arg
  // or it is referenced by global variables
  if (!isa<GetElementPtrInst>(v))
    return "";
  auto GEI = cast<GetElementPtrInst>(v);
  auto name = handleType(GEI->getSourceElementType()).str();
  if (name.find(".", 7) != string::npos) {
    name = name.substr(0, name.find(".", 7));
  }
  if (name == "") {
    return name;
  }
  // for (unsigned i = 1; i < GEI->getNumOperands(); i++) {
  //   if (auto constInt = dyn_cast<ConstantInt>(GEI->getOperand(i))) {
  //     name += ".";
  //     name += std::to_string(constInt->getZExtValue());
  //   }
  // }

  // // check if these are two GEIs
  // if (auto GEIOuter = dyn_cast<GetElementPtrInst>(GEI->getOperand(0))) {
  //   auto outName = handleType(GEIOuter->getSourceElementType()).str();
  //   if (outName == "") {
  //     return name;
  //   }
  //   for (unsigned i = 1; i < GEI->getNumOperands(); i++) {
  //     if (auto constInt = dyn_cast<ConstantInt>(GEI->getOperand(i))) {
  //       outName += ".";
  //       outName += std::to_string(constInt->getZExtValue());
  //     }
  //   }
  //   name = outName + "." + name;
  // }

  if (StructType *st = dyn_cast<StructType>(GEI->getSourceElementType())) {
    if (auto ci =
            dyn_cast<ConstantInt>(GEI->getOperand(GEI->getNumOperands() - 1))) {
      Module *M = GEI->getParent()->getModule();
      DataLayout DL = M->getDataLayout();
      const StructLayout *sl = DL.getStructLayout(st);
      uint64_t offset = sl->getElementOffset((unsigned)ci->getZExtValue());
      name += " " + std::to_string(offset);
      return name;
    }
  }
  return "";
}

// return true if the value is from
// arg or gloabl
bool ChangeAnalysisPass::isFromGlobal(Value *v) {
  ValueSet trackSet;
  doBackward(v, trackSet);
  for (auto v : trackSet) {
    if (isa<Argument>(v) || isa<GlobalVariable>(v)) {
      return true;
    }
  }
  return false;
}

std::set<string> ChangeAnalysisPass::forwardAnalysis(Value *v) {
  // step 1: find representation obj+offset, make sure the value is from arg or
  // global
  // step 2: do recursive forward analysis with the representation
  ValueSet trackSet;
  ValueSet curSet;
  std::set<string> postAccess;
  doBackward(v, curSet);
  trackSet.insert(curSet.begin(), curSet.end());

  string repr = "";
  for (auto visited : curSet) {
    repr = findIntraRepresentation(visited);
    if (repr != "") {
      postAccess.insert(repr);
    }
  }

  for (auto visited : curSet) {
    if (auto arg = dyn_cast<Argument>(visited)) {
      unsigned idx = arg->getArgNo();

      // find caller, and then backward
      for (auto callInst : Ctx->Callers[arg->getParent()]) {
        doBackward(callInst->getArgOperand(idx), trackSet);
      }
    }
  }

  for (auto visited : trackSet) {
    repr = findIntraRepresentation(visited);
    if (repr != "") {
      postAccess.insert(repr);
    }
  }

  if (postAccess.size() == 0) {
    // KA_WARNS(0, "forward analysis failed");
  }
  return postAccess;
}

void ChangeAnalysisPass::backwardAnalysis(Value *v, ValueSet &trackSet) {
  ValueSet curSet;
  doBackward(v, curSet);
  trackSet.insert(curSet.begin(), curSet.end());

  for (auto visited : curSet) {
    if (auto arg = dyn_cast<Argument>(visited)) {
      Function *F = arg->getParent();

      for (unsigned i = 0; i < F->arg_size(); i++) {
        if (arg == F->getArg(i)) {
          // find caller, and then backward
          for (auto callInst : Ctx->Callers[F]) {
            doBackward(callInst->getArgOperand(i), trackSet);
          }
        }
      }
    }
  }
}

// stop at current func
// intra analysis
void ChangeAnalysisPass::doBackward(Value *v, ValueSet &trackSet) {
  if (v == nullptr)
    return;

  if (!trackSet.insert(v).second) {
    return;
  }

  KA_LOGS(1, "backwarding " << *v);

  if (isa<Argument>(v)) {
    KA_LOGS(1, "reached argument " << *v);
    return;
  }

  if (!isa<Instruction>(v)) {
    return;
  }

  Instruction *I = cast<Instruction>(v);
  switch (I->getOpcode()) {
  case Instruction::Store:
    /* code */
    assert(0 && "should not taint to store");
    break;

  case Instruction::Load: {
    doBackward(I->getOperand(0), trackSet);
    break;
  }

  case Instruction::Call: {
    CallInst *CI = cast<CallInst>(I);
    for (auto AI = CI->arg_begin(), E = CI->arg_end(); AI != E; AI++) {
      Value *arg = dyn_cast<Value>(&*AI);
      if (dyn_cast<Constant>(arg)) {
        continue;
      }
      doBackward(arg, trackSet);
    }
    break;
  }

  case Instruction::GetElementPtr: {
    doBackward(I->getOperand(0), trackSet);
    break;
  }

  case Instruction::PHI: {
    // handle nodes
    KA_LOGS(1, "PHI node " << *I);
    auto PHI = cast<PHINode>(I);
    for (unsigned i = 0; i < PHI->getNumIncomingValues(); i++) {
      doBackward(PHI->getIncomingValue(i), trackSet);
      KA_LOGS(1, "incoming value " << *PHI->getIncomingValue(i));
    }
    break;
  }

  case Instruction::Alloca: {
    break;
  }

  case Instruction::ICmp:
    // assert(0 && "This should not happen");
  case Instruction::FCmp:
    // assert(0 && "This should not happen");
  case Instruction::Add:
  case Instruction::FAdd:
  case Instruction::Sub:
  case Instruction::FSub:
  case Instruction::Mul:
  case Instruction::FMul:
  case Instruction::UDiv:
  case Instruction::SDiv:
  case Instruction::FDiv:
  case Instruction::URem:
  case Instruction::SRem:
  case Instruction::FRem:
  case Instruction::Shl:
  case Instruction::LShr:
  case Instruction::AShr:
  case Instruction::And:
  case Instruction::Or:
  case Instruction::Xor:
  case Instruction::Trunc:
  case Instruction::ZExt:
  case Instruction::SExt:
  case Instruction::FPToUI:
  case Instruction::FPToSI:
  case Instruction::UIToFP:
  case Instruction::SIToFP:
  case Instruction::FPTrunc:
  case Instruction::FPExt:
  case Instruction::PtrToInt:
  case Instruction::IntToPtr:
  case Instruction::AddrSpaceCast:
  case Instruction::Select: {
    for (unsigned i = 0, e = I->getNumOperands(); i != e; i++) {
      auto ope = I->getOperand(i);
      if (dyn_cast<Constant>(ope)) {
        continue;
      }
      // taint value
      // mergeSet(result, taintAnalysis(V, vs, found));
      doBackward(ope, trackSet);
    }
    break;
  }
  default: {
    if (isa<CastInst>(I)) {
      doBackward(I->getOperand(0), trackSet);
    }
    break;
  }
  }
}

// TODO: handle argument
std::set<string> ChangeAnalysisPass::condRepr(Value *v,
                                              std::set<Value *> &tracked) {
  // others: value op value
  KA_LOGS(2, "got v " << *v);
  std::set<string> out;
  if (v == nullptr)
    return out;

  if (!tracked.insert(v).second) {
    return out;
  }

  if (!isa<Instruction>(v)) {
    return out;
  }

  // remove CastInst
  while (isa<CastInst>(v)) {
    auto CI = cast<CastInst>(v);
    v = CI->getOperand(0);
  }

  if (!isa<Instruction>(v)) {
    return out;
  }

  Instruction *I = cast<Instruction>(v);
  // KA_LOGS(1, "op name " << I->getOpcodeName());
  // KA_LOGS(1, "Instruction " << *I);
  switch (I->getOpcode()) {
  // case Instruction::PHI:
  case Instruction::Call: {
    Function *F = cast<CallInst>(I)->getCalledFunction();
    if (!F || (F && !F->hasName()))
      return out;
    // TODO: extract cond from function
    // return F->getName().str();
    for (int i = 0; i < I->getNumOperands(); i++) {
      // auto subRepr = condRepr(I->getOperand(i), tracked);
      // out.insert(subRepr.begin(), subRepr.end());
    }
    return out;
  }

  case Instruction::Load:
    // resolve the loaded value as the address of loading
    return condRepr(I->getOperand(0), tracked);

  case Instruction::GetElementPtr: {
    GetElementPtrInst *GEI = cast<GetElementPtrInst>(I);
    auto name = handleType(GEI->getSourceElementType()).str();
    if (name.find(".", 7) != string::npos) {
      name = name.substr(0, name.find(".", 7));
    }

    if (StructType *st = dyn_cast<StructType>(GEI->getSourceElementType())) {
      if (auto ci = dyn_cast<ConstantInt>(
              GEI->getOperand(GEI->getNumOperands() - 1))) {
        Module *M = I->getParent()->getModule();
        DataLayout DL = M->getDataLayout();
        const StructLayout *sl = DL.getStructLayout(st);
        uint64_t offset = sl->getElementOffset((unsigned)ci->getZExtValue());
        KA_LOGS(1, "Got offset " << offset);
        name += " " + std::to_string(offset);
        out.insert(name);
      }
    }
    return out;
  }
  case Instruction::ICmp: {
    auto ICMP = cast<ICmpInst>(I);
    auto name = ICMP->getPredicateName(ICMP->getPredicate()).str();
    for (unsigned i = 0; i < ICMP->getNumOperands(); i++) {
      auto subRepr = condRepr(ICMP->getOperand(i), tracked);
      out.insert(subRepr.begin(), subRepr.end());
    }
    return out;
  }
  // avoid potential path explosion
  case Instruction::PHI: {
    for (int i = 0; i < I->getNumOperands(); i++) {
      auto subRepr = condRepr(I->getOperand(i), tracked);
      out.insert(subRepr.begin(), subRepr.end());
    }
    return out;
  }
  default:
    break;
  }

  if (I->isUnaryOp() || I->isBinaryOp()) {
    auto name = std::string(I->getOpcodeName()) + " ";
    for (int i = 0; i < I->getNumOperands(); i++) {
      auto subRepr = condRepr(I->getOperand(i), tracked);
      out.insert(subRepr.begin(), subRepr.end());
    }
    return out;
  }

  return out;
}

void ChangeAnalysisPass::handleCondNode(CondNode condNode, Value *v) {
  if (!condNode.first || !isa<Instruction>(condNode.first))
    return;
  KA_LOGS(1, "cond : " << *condNode.first);

  auto DbgLoc = cast<Instruction>(condNode.first)->getDebugLoc();
  Function *F = cast<Instruction>(condNode.first)->getFunction();
  std::string loc = "";
  if (DbgLoc) {
    loc = DbgLoc->getScope()->getFilename().str() + " ";
    loc += std::to_string(DbgLoc->getLine());
    if (F)
      loc += " " + F->getName().str();
    else
      loc += " NULL";
    KA_LOGS(1, "got loc " << loc);
    condLoc.insert(loc);
  }
  // extract variables in cond node
  std::set<Value *> tracked;
  tracked.clear();
  auto repr = condRepr(condNode.first, tracked);
  for (auto r : repr) {
    condVar.insert(r + " " + loc);
  }
  // condVar.insert(repr.begin(), repr.end());
  for (auto r : repr) {
    KA_LOGS(1, " got repr " << r);
  }
}

void ChangeAnalysisPass::Refine() {
  KA_LOGS(0, "doing refinement");

  std::set<Function *> Fset;
  for (auto ele : newDef) {
    // check if brand new defined function
    if (auto F = dyn_cast<Function>(ele.first)) {
      Fset.insert(F);
    }
  }

  // analyze the new define function
  for (auto F : Fset) {
    if (F->empty() || F->isDeclaration())
      continue;

    auto genSetPair = analyzeFuncUse(F);
    for (auto define : genSetPair.first) {
      if (define.second.size() == 0) {
        CondVal condVal;
        genSetInsert(newDef, define.first, condVal);
      } else {
        for (auto condVal : define.second)
          genSetInsert(newDef, define.first, condVal);
      }
    }
  }

  // TODO: if new function call in newDef and deadDef,
  // how do we propogate them, we plan to make it as
  // an inlined function
  // do so before doing the propogation
  GenSet funcSet;
  for (auto ele : newDef) {
    if (isa<CallInst>(ele.first)) {
      funcSet[ele.first] = ele.second;
    }
  }

  for (auto ele : funcSet) {
    assert(isa<CallInst>(ele.first));
    auto CI = dyn_cast<CallInst>(ele.first);
    Function *F = CI->getCalledFunction();
    if (!F || F->empty() || F->isDeclaration())
      continue;
    // get the precond from ele.second
    Cond preCond;
    for (auto condVal : ele.second) {
      preCond = condVal.first;
    }
    // new defintion in genSetPair
    auto genSetPair = analyzeFuncUse(F);
    KA_LOGS(0, "result of genset\n");
    dump(genSetPair.first);
    dump(genSetPair.second);
    for (auto define : genSetPair.first) {
      if (define.second.size() == 0) {
        CondVal condVal;
        condVal.first = preCond;
        genSetInsert(newDef, define.first, condVal);
      } else {
        for (auto condVal : define.second) {
          // add precond to the result

          // copy precond
          Cond curPreCond(preCond);
          for (auto condNode : condVal.first) {
            curPreCond.push_back(condNode);
          }
          condVal.first = curPreCond;
          KA_LOGS(0, "got new define from new function call \n");
          KA_LOGS(0, "addr " << *define.first << "\n");
          KA_LOGS(0, "cond: \n");
          dump(condVal);
          genSetInsert(newDef, define.first, condVal);
        }
      }
    }
  }

  funcSet.clear();
  for (auto ele : deadDef) {
    if (isa<CallInst>(ele.first)) {
      funcSet[ele.first] = ele.second;
    }
  }

  for (auto ele : funcSet) {
    assert(isa<CallInst>(ele.first));
    auto CI = dyn_cast<CallInst>(ele.first);
    Function *F = CI->getCalledFunction();
    if (!F || F->empty() || F->isDeclaration())
      continue;
    // get the precond from ele.second
    Cond preCond;
    for (auto condVal : ele.second) {
      preCond = condVal.first;
    }
    // new defintion in genSetPair
    auto genSetPair = analyzeFuncUse(F);
    KA_LOGS(0, "result of genset\n");
    dump(genSetPair.first);
    dump(genSetPair.second);
    for (auto define : genSetPair.first) {
      if (define.second.size() == 0) {
        CondVal condVal;
        condVal.first = preCond;
        genSetInsert(deadDef, define.first, condVal);
      } else {
        for (auto condVal : define.second) {
          // add precond to the result

          // copy precond
          Cond curPreCond(preCond);
          for (auto condNode : condVal.first) {
            curPreCond.push_back(condNode);
          }
          condVal.first = curPreCond;
          KA_LOGS(0, "got dead define from dead function call \n");
          KA_LOGS(0, "addr " << *define.first << "\n");
          KA_LOGS(0, "cond: \n");
          dump(condVal);
          genSetInsert(deadDef, define.first, condVal);
        }
      }
    }
  }

  for (auto ele : newDef) {
    if (isa<Function>(ele.first))
      continue;
    KA_LOGS(0, "new define " << *ele.first);
    if (resNode.find(ele.first) == resNode.end()) {
      ValueSet vs1;
      std::set<CondNode> vs2;
      resNode[ele.first] = std::make_pair(vs1, vs2);
    }
    resPost[ele.first] = forwardAnalysis(ele.first);

    std::set<string> pre;
    for (auto condVal : ele.second) {
      resPre[condVal.second] = forwardAnalysis(condVal.second);
      pre.insert(resPre[condVal.second].begin(), resPre[condVal.second].end());
      // handle the conditions for condVal.second
      for (auto condNode : condVal.first) {
        handleCondNode(condNode, ele.first);
      }
    }

    Instruction *SI = storeMap[ele.first];
    if (Result.find(SI) == Result.end()) {
      Result[SI] = std::make_pair(pre, resPost[ele.first]);
    }
  }

  for (auto ele : deadDef) {
    KA_LOGS(0, "dead define " << *ele.first);
    if (resNode.find(ele.first) == resNode.end()) {
      ValueSet vs1;
      std::set<CondNode> vs2;
      resNode[ele.first] = std::make_pair(vs1, vs2);
    }
    resPost[ele.first] = forwardAnalysis(ele.first);

    std::set<string> pre;
    for (auto condVal : ele.second) {
      // resPost[condVal.second] = forwardAnalysis(condVal.second);

      // handle the conditions for condVal.second
      for (auto condNode : condVal.first) {
        handleCondNode(condNode, ele.first);
      }
    }

    Instruction *SI = storeMap[ele.first];
    if (Result.find(SI) == Result.end()) {
      Result[SI] = std::make_pair(pre, resPost[ele.first]);
    }
  }

  for (auto ele : newUse) {
    KA_LOGS(0, "new use " << *ele.first);
    if (resNode.find(ele.first) == resNode.end()) {
      ValueSet vs1;
      std::set<CondNode> vs2;
      resNode[ele.first] = std::make_pair(vs1, vs2);
    }
    resPre[ele.first] = forwardAnalysis(ele.first);

    for (auto condVal : ele.second) {
      // handle the conditions for condVal.second
      for (auto condNode : condVal.first) {
        handleCondNode(condNode, ele.first);
      }
    }

    Instruction *LI = loadMap[ele.first];
    if (Result.find(LI) == Result.end()) {
      std::set<string> post;
      Result[LI] = std::make_pair(resPre[ele.first], post);
    }
  }
}

GenSetPair ChangeAnalysisPass::analyzeFuncUse(Function *F) {
  BasicBlockPair BP;
  GenSetPair genSetPair;

  BP.first = &F->front();
  BP.second = &F->back();

  if (!BP.first || !BP.second) {
    return genSetPair;
  }

  if (F->getName().find("list_") != std::string::npos)
    return genSetPair;

  if (F->getName().find("spin_") != std::string::npos)
    return genSetPair;

  auto vars = findVariables(F);
  genSetPair = analyzeValueSetRange(BP, vars);
  return genSetPair;
}

void ChangeAnalysisPass::doAnalysis(BasicBlock *b1, BasicBlock *b2) {
  // 1. perform preprocess
  BasicBlockPair raw = findRange(b1);
  BasicBlockPair patched = findRange(b2);

  if (!raw.first || !raw.second)
    return;

  // TODO: check raw.second must be the same as patched.second

  // 2. value set analysis (analyze the abstract semantics of values)
  // 2.1 find variables we care about to represent the values
  rawVars = findVariables(b1->getParent());
  patchedVars = findVariables(b2->getParent());

  // 2.2 forward analysis, and a fixed point, smallest solution of the result
  GenSetPair rawPair = analyzeValueSetRange(raw, rawVars);
  GenSetPair patchedPair = analyzeValueSetRange(patched, patchedVars);

  KA_LOGS(0, "dumping raw analysis result");
  dump(rawPair.first);
  dump(rawPair.second);

  KA_LOGS(0, "dumping patched analysis result");
  dump(patchedPair.first);
  dump(patchedPair.second);

  // 3. compare two sets
  KA_LOGS(0, "doing comparasion");
  compareValues(rawPair, patchedPair);

  // exit(0);
  // 4. refinement
  // move refinement
}

void ChangeAnalysisPass::storeRes() {

  ofstream result;
  result.open("/tmp/cond.txt", std::ios_base::app);
  KA_LOGS(0, "cond var");
  for (auto var : condVar) {
    result << var << "\n";
    KA_LOGS(0, var);
  }
  result.close();

  result.open("/tmp/prop.txt", std::ios_base::app);
  KA_LOGS(0, "def use propa");
  for (auto res : Result) {
    if (!res.second.first.size() && !res.second.second.size()) {
      continue;
    }

    auto DbgLoc = res.first->getDebugLoc();
    auto F = res.first->getFunction();
    if (DbgLoc) {
      auto loc = DbgLoc->getScope()->getFilename().str() + " ";
      loc += std::to_string(DbgLoc->getLine());
      if (F)
        loc += " " + F->getName().str();
      else
        loc += " NULL";
      KA_LOGS(1, "got loc " << loc);

      // store result
      result << loc << "\n";
      for (auto pre : res.second.first) {
        result << pre << "\n";
      }
      result << "------\n";
      for (auto post : res.second.second) {
        result << post << "\n";
      }
      result << "------\n";
    }
  }

  return;
}

void ChangeAnalysisPass::run() {

  if (DisableLLVMDiff) {
    Function *raw = rawModule->getFunction(changedFunc->getName());
    Function *patched = patchedModule->getFunction(changedFunc->getName());

    doAnalysis(&raw->getEntryBlock(), &patched->getEntryBlock());
    Refine();
    storeRes();
    return;
  }
  // step 1
  // do llvm diff, find differrent functions and basic block
  // FIXME: only generates the first diff in a function
  DiffConsumer Consumer;
  DifferenceEngine Engine(Consumer);
  Engine.diff(rawModule, patchedModule);
  bool analyzed = false;

  KA_LOGS(0, "llvm bitcode diff done, start analyzing the diff...\n");

  // preprocess: find diffed basic blocks and their common post-dominator
  if (Consumer.diff.size() || Consumer.diffFunc.size()) {
    for (auto d : Consumer.diff) {
      // {funcName : {b1, b2}}
      // outs() << d.first << ":" << d.second.size() << "\n";
      for (auto bb : d.second) {

        if (bb.first->getParent()->getName() != changedFunc->getName()) {
          // outs() << "skiping function " << bb.first->getParent()->getName()
          //        << "\n";
          continue;
        } else {
          outs() << "analyzing function " << changedFunc->getName() << "\n";
        }

        KA_LOGS(0, "left: " << *bb.first);
        KA_LOGS(0, "right: " << *bb.second);
#ifdef WHOLE_FUNC_ANALYZE
        if (analyzed)
          continue;
#endif
        doAnalysis(bb.first, bb.second);
        analyzed = true;
      }
    }

    for (auto newFunc : Consumer.diffFunc) {
      if (newFunc->isDeclaration())
        continue;
      KA_LOGS(0,
              "brand new function defined, checking if it is in new defset\n");
      bool exist = false;
      for (auto condv : newDef) {
        if (exist)
          break;
        if (auto CI = dyn_cast<CallInst>(condv.first)) {
          Function *F = CI->getCalledFunction();
          if (!F)
            continue;
          if (F->getName() == newFunc->getName()) {
            exist = true;
          }
        }
      }

      // if (!exist) {
      //   KA_WARNS(0, "brand new defined function not called\n");
      //   CondVal condVal;
      //   genSetInsert(newDef, newFunc, condVal);
      // }

      // add them anyway
      CondVal condVal;
      genSetInsert(newDef, newFunc, condVal);
    }
    Refine();
    storeRes();
  }
}
