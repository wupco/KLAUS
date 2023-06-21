/*
 * main function
 *
 * Copyright (C) 2012 Xi Wang, Haogang Chen, Nickolai Zeldovich
 * Copyright (C) 2015 Byoungyoung Lee
 * Copyright (C) 2015 - 2019 Chengyu Song
 * Copyright (C) 2016 Kangjie Lu
 * Copyright (C) 2019 Yueqi Chen
 *
 * For licensing details see LICENSE
 */

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/SystemUtils.h>
#include <llvm/Support/ToolOutputFile.h>

#include <fstream>
#include <memory>
#include <sstream>
#include <sys/resource.h>
#include <vector>

#include "CallGraph.h"
#include "ChangeAnalysis.h"
#include "GlobalCtx.h"
#include "StructFinder.h"

using namespace llvm;

cl::list<std::string> InputFilenames(cl::Positional, cl::OneOrMore,
                                     cl::desc("<input bitcode files>"));

cl::opt<unsigned>
    VerboseLevel("debug-verbose",
                 cl::desc("Print information about actions taken"),
                 cl::init(0));

cl::opt<unsigned> DisableLLVMDiff("disable-llvm-diff",
                                  cl::desc("Disable LLVM diff"), cl::init(0));

cl::opt<std::string> DumpLocation("dump-location",
                                  cl::desc("dump found structures"),
                                  cl::NotHidden, cl::init(""));

cl::opt<std::string> PatchedFuncName("func", cl::desc("function got patched"),
                                     cl::NotHidden, cl::init(""));

cl::opt<std::string> RawBC("raw-bc", cl::desc("raw bitcode file"),
                           cl::NotHidden, cl::init(""));

cl::opt<std::string> PatchedBC("patched-bc",
                               cl::desc("bitcode file got patched"),
                               cl::NotHidden, cl::init(""));

GlobalContext GlobalCtx;

void IterativeModulePass::run(ModuleList &modules) {

  ModuleList::iterator i, e;

  KA_LOGS(3, "[" << ID << "] Initializing " << modules.size() << " modules.");
  bool again = true;
  while (again) {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      KA_LOGS(3, "[" << i->second << "]");
      again |= doInitialization(i->first);
    }
  }

  KA_LOGS(3, "[" << ID << "] Processing " << modules.size() << " modules.");
  unsigned iter = 0, changed = 1;
  while (changed) {
    ++iter;
    changed = 0;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      KA_LOGS(3, "[" << ID << " / " << iter << "] ");
      // FIXME: Seems the module name is incorrect, and perhaps it's a bug.
      KA_LOGS(3, "[" << i->second << "]");

      bool ret = doModulePass(i->first);
      if (ret) {
        ++changed;
        KA_LOGS(3, "\t [CHANGED]");
      } else {
        KA_LOGS(3, " ");
      }
    }
    KA_LOGS(3, "[" << ID << "] Updated in " << changed << " modules.");
  }

  KA_LOGS(3, "[" << ID << "] Finalizing " << modules.size() << " modules.");
  again = true;
  while (again) {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      again |= doFinalization(i->first);
    }
  }

  KA_LOGS(3, "[" << ID << "] Done!\n");
  return;
}

void doBasicInitialization(Module *M) {

  // collect global object definitions
  for (GlobalVariable &G : M->globals()) {
    if (G.hasExternalLinkage())
      GlobalCtx.Gobjs[G.getName().str()] = &G;
  }

  // collect global function definitions
  for (Function &F : *M) {
    if (F.hasExternalLinkage() && !F.empty()) {
      // external linkage always ends up with the function name
      StringRef FNameRef = F.getName();
      std::string FName = "";
      if (FNameRef.startswith("__sys_"))
        FName = "sys_" + FNameRef.str().substr(6);
      else
        FName = FNameRef.str();
      // fprintf(stderr, "FName: %s\n", FName.c_str());
      // assert(GlobalCtx.Funcs.count(FName) == 0); // force only one defintion
      GlobalCtx.Funcs[FName] = &F;
    }
  }

  return;
}

int main(int argc, char **argv) {

#ifdef SET_STACK_SIZE
  struct rlimit rl;
  if (getrlimit(RLIMIT_STACK, &rl) == 0) {
    rl.rlim_cur = SET_STACK_SIZE;
    setrlimit(RLIMIT_STACK, &rl);
  }
#endif

  // Print a stack trace if we signal out.
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 9
  sys::PrintStackTraceOnErrorSignal();
#else
  sys::PrintStackTraceOnErrorSignal(StringRef());
#endif
  PrettyStackTraceProgram X(argc, argv);

  cl::ParseCommandLineOptions(argc, argv, "global analysis");
  SMDiagnostic Err;

  assert(RawBC != "" && PatchedBC != "");

  // load raw
  LLVMContext LLVMCtx_;
  std::unique_ptr<Module> M_raw = parseIRFile(RawBC, Err, LLVMCtx_);
  assert(M_raw != NULL && "load raw bc");
  Module *rawModule = M_raw.get();

  // load patched
  std::unique_ptr<Module> M_patched = parseIRFile(PatchedBC, Err, LLVMCtx_);
  assert(M_patched != NULL && "load patched bc");
  Module *patchedModule = M_patched.get();

  // Load modules
  KA_LOGS(0, "Total " << InputFilenames.size() << " file(s)");

  for (unsigned i = 0; i < InputFilenames.size(); ++i) {
    // Use separate LLVMContext to avoid type renaming
    KA_LOGS(0, "[" << i << "] " << InputFilenames[i] << "");
    LLVMContext *LLVMCtx = new LLVMContext();
    std::unique_ptr<Module> M = parseIRFile(InputFilenames[i], Err, *LLVMCtx);

    if (M == NULL) {
      errs() << argv[0] << ": error loading file '" << InputFilenames[i]
             << "'\n";
      continue;
    } else {
      errs() << "loaded\n";
    }

    Module *Module = M.release();
    StringRef MName = StringRef(strdup(InputFilenames[i].data()));
    GlobalCtx.Modules.push_back(std::make_pair(Module, MName));
    GlobalCtx.ModuleMaps[Module] = InputFilenames[i];
    doBasicInitialization(Module);
  }

  // no call graph is needed currently
  CallGraphPass CGPass(&GlobalCtx);
  CGPass.run(GlobalCtx.Modules);

  Function *changedFunc = nullptr;
  if (PatchedFuncName != "") {
    changedFunc = rawModule->getFunction(PatchedFuncName);
    Function *FuncPatched = patchedModule->getFunction(PatchedFuncName);
    assert(changedFunc != NULL && FuncPatched != NULL);
  }

  ChangeAnalysisPass CAP(&GlobalCtx, rawModule, patchedModule, changedFunc);
  CAP.run();

  return 0;
}
