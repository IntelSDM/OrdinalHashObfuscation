#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"

struct OrdinalHashPass : llvm::PassInfoMixin<OrdinalHashPass>
{
    llvm::PreservedAnalyses run(llvm::Module& m, llvm::ModuleAnalysisManager&);
};

bool RunOrdinalHash(llvm::Module& m);

extern llvm::cl::opt<bool> OrdHashEnable;