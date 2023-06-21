#ifndef CA_H_
#define CA_H_

#include "GlobalCtx.h"

typedef std::pair<BasicBlock *, BasicBlock *> BasicBlockPair;
typedef std::set<Value *> ValueSet;

// cond: vector cond1, cond2
// addr, {(cond, val)}
typedef std::pair<Value *, bool> CondNode;
typedef std::vector<CondNode> Cond; // the order of condnode should not matter
typedef std::set<Cond> CondSet;
typedef std::pair<Cond, Value *> CondVal;
typedef std::map<Value *, std::set<CondVal>> GenSet;
typedef std::pair<GenSet, GenSet> GenSetPair;

class ChangeAnalysisPass {
private:
  // llvm::Function *rawFunc;
  // llvm::Function *patchedFunc;

  llvm::Module *rawModule;
  llvm::Module *patchedModule;
  llvm::Function *changedFunc;
  std::map<Function *, AAResults *> aliasMap;

  // from dbgVar to debugInst
  std::map<Value *, Value *> DbgMap;
  std::set<Value *> rawVars;
  std::set<Value *> patchedVars;
  // std::map<Value*, Value*> patchedDbgMap;

  GenSet newDef, deadDef, newUse;

  // condVar stores obj + offset for conditional variables
  std::set<string> condVar;
  // condLoc stores cond locations like file:line
  std::set<string> condLoc;

  // std::set<string> postAccess;

  // value : (propagated node set , condition set)
  std::map<Value *, std::pair<ValueSet, std::set<CondNode>>> resNode;
  std::map<Value *, std::set<string>> resPost;
  std::map<Value *, std::set<string>> resPre;

  // map use to load inst
  std::map<Value *, Instruction *> loadMap;
  // map store addr to store inst
  std::map<Value *, Instruction *> storeMap;

  GlobalContext *Ctx;

public:
  // node, pre, post
  std::map<Instruction *, std::pair<std::set<string>, std::set<string>>> Result;
  ChangeAnalysisPass(GlobalContext *Ctx_, Module *rawModule_,
                     Module *patchedModule_, Function *changedFunc_) {
    Ctx = Ctx_;
    rawModule = rawModule_;
    patchedModule = patchedModule_;
    changedFunc = changedFunc_;
  }

  CondNode getCond(BasicBlockPair pair, ValueSet vars);
  bool isSameCondNode(CondNode cNodeA, CondNode cNodeB);
  bool isSameCond(Cond condA, Cond condB);
  bool containCondNode(Cond cond, CondNode condNode);
  bool containCondNode(Cond cond, CondNode condNode, std::set<Value *> condAVar,
                       std::set<Value *> condBVar);
  int containCondNodeBranch(Cond cond, CondNode condNode);
  Cond reverseCond(Cond condA, Cond condB, std::set<Value *> condAVar,
                   std::set<Value *> condBVar);
  int findCondNode(Cond cond, CondNode condNode);
  bool sanitizeCond(Cond &cond, CondNode condNode);

  bool condNodeMatch(CondNode condNodeA, CondNode condNodeB);
  bool condMatch(Cond condA, Cond condB);
  bool condValMatch(CondVal condValA, CondVal condValB);

  StringRef handleType(Type *ty);
  Value *resolveValue(Value *v, ValueSet vars);
  string strValue(Value *v, ValueSet vars);
  std::set<string> condRepr(Value *v, std::set<Value *> &tracked);
  bool addCond(GenSet &GS, CondNode condNode);
  void unionSet(GenSet &setA, GenSet setB, CondNode condNode);
  bool unionSet(GenSet &setA, GenSet setB);
  bool unionCondSet(CondSet &setA, CondSet setB);

  bool analyzeBasicBlock(BasicBlock *b,
                         /* variable we care about */ ValueSet vars,
                         CondSet preCondSet,
                         /* */ std::map<Value *, std::set<CondVal>> &defInfo,
                         /* */ std::map<Value *, std::set<CondVal>> &useInfo);
  GenSetPair analyzeValueSetRange(BasicBlockPair pair, ValueSet vars);
  std::set<Value *> findVariables(Function *func);
  void compareValues(GenSetPair, GenSetPair);
  std::set<string> forwardAnalysis(Value *v);
  void backwardAnalysis(Value *v, ValueSet &trackSet);
  void doForward(Value *v, ValueSet &trackSet);
  void doBackward(Value *v, ValueSet &trackSet);
  bool isFromGlobal(Value *v);
  string findIntraRepresentation(Value *v);
  BasicBlockPair findRange(BasicBlock *);
  void handleCondNode(CondNode condNode, Value *v);
  void Refine();
  GenSetPair analyzeFuncUse(Function *F);
  void doAnalysis(BasicBlock *b1, BasicBlock *b2);
  void run();
  void storeRes();

  // debug log
  void dump(GenSet valCondSet) {
    KA_LOGS(0, "=======================================");
    KA_LOGS(0, "start dumping value set");
    for (auto ele : valCondSet) {
      KA_LOGS(0, "addr: " << *ele.first);
      for (auto condVal : ele.second) {
        // if (condVal.second) {
        //   KA_LOGS(0, "  def value: " << *condVal.second);
        // }
        // for (unsigned i = 0; i < condVal.first.size(); i++) {
        //   if (!condVal.first[i].first)
        //     continue;
        //   KA_LOGS(0, "  cond " << i << ": " << *condVal.first[i].first << " "
        //                        << condVal.first[i].second);
        // }
        dump(condVal);
      }
      KA_LOGS(0, "-----------------------------------");
    }
    KA_LOGS(0, "end of dumping value set");
    KA_LOGS(0, "=======================================");
  };

  void dump(std::set<CondVal> condValSet) {
    KA_LOGS(0, "size of cond " << condValSet.size());
    for (auto condVal : condValSet) {
      dump(condVal);
    }
  };

  void dump(CondSet condSet) {
    KA_LOGS(0, "dumping condition set");
    unsigned num = 0;
    for (auto cond : condSet) {
      KA_LOGS(0, "cond " << num++);
      for (unsigned i = 0; i < cond.size(); i++) {
        if (!cond[i].first)
          continue;
        KA_LOGS(0, "  condNode " << i << ": " << *cond[i].first << ","
                                 << cond[i].second);
      }
    }
  };

  void dump(CondVal condVal) {
    KA_LOGS(0, "size of cond " << condVal.first.size());
    for (unsigned i = 0; i < condVal.first.size(); i++) {
      if (!condVal.first[i].first) {
        KA_LOGS(0, " condNode nullptr, empty condition");
        continue;
      }
      KA_LOGS(0, "  condNode " << i << ": " << *condVal.first[i].first
                               << ", true branch?" << condVal.first[i].second);
    }
  };

  void dump(Cond cond) {
    for (unsigned i = 0; i < cond.size(); i++) {
      if (!cond[i].first) {
        KA_LOGS(0, " condNode nullptr, empty condition");
        continue;
      }
      KA_LOGS(0, "  condNode " << i << ": " << *cond[i].first << ","
                               << cond[i].second);
    }
  };
};

#endif