#include "OrdinalHashPass.h"
#include "MMOPrimitives.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IntrinsicsX86.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/CommandLine.h"

#include <cstdint>
#include <string>
#include <vector>

using namespace llvm;

llvm::cl::opt<bool> OrdHashEnable("obfordinalhash", llvm::cl::init(true), llvm::cl::desc("Master Toggle"));

static unsigned SiteCounter = 0;

struct Site
{
    ICmpInst* Cmp;
    CmpInst::Predicate EffectivePred;
    Value* V;
    uint64_t CBits;
    unsigned BitWidth;
    bool IsSigned;
};

static bool HasAnnotationTag(Function& f, const char* tag)
{
    Module* m = f.getParent();
    GlobalVariable* ga = m->getGlobalVariable("llvm.global.annotations");
    if (!ga) return false;
    ConstantArray* ca = dyn_cast<ConstantArray>(ga->getOperand(0));
    if (!ca) return false;
    for (unsigned i = 0; i < ca->getNumOperands(); ++i)
    {
        ConstantStruct* cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
        if (!cs) continue;
        if (cs->getOperand(0)->stripPointerCasts() != &f) continue;
        auto* strgv = dyn_cast<GlobalVariable>(cs->getOperand(1)->stripPointerCasts());
        if (!strgv || !strgv->hasInitializer()) continue;
        auto* cds = dyn_cast<ConstantDataSequential>(strgv->getInitializer());
        if (!cds || !cds->isString()) continue;
        if (strcmp(cds->getAsString().str().c_str(), tag) == 0) return true;
    }
    return false;
}

static bool HasNoObfuscateAnnotation(Function& f)
{
    return HasAnnotationTag(f, "noobfus");
}

static bool IsOrdinalPred(CmpInst::Predicate p)
{
    switch (p)
    {
        case CmpInst::ICMP_SLT:
        case CmpInst::ICMP_SLE:
        case CmpInst::ICMP_SGT:
        case CmpInst::ICMP_SGE:
        case CmpInst::ICMP_ULT:
        case CmpInst::ICMP_ULE:
        case CmpInst::ICMP_UGT:
        case CmpInst::ICMP_UGE: return true;
        default: return false;
    }
}

static bool IsSignedOrdinal(CmpInst::Predicate p)
{
    return p == CmpInst::ICMP_SLT || p == CmpInst::ICMP_SLE || p == CmpInst::ICMP_SGT || p == CmpInst::ICMP_SGE;
}

static CmpInst::Predicate FinalPredFor(CmpInst::Predicate p)
{
    switch (p)
    {
        case CmpInst::ICMP_ULT: return CmpInst::ICMP_SLT;
        case CmpInst::ICMP_ULE: return CmpInst::ICMP_SLE;
        case CmpInst::ICMP_UGT: return CmpInst::ICMP_SGT;
        case CmpInst::ICMP_UGE: return CmpInst::ICMP_SGE;
        default: return p;
    }
}

static void CollectSites(Function& f, std::vector<Site>& out)
{
    for (BasicBlock& bb : f)
    {
        for (Instruction& i : bb)
        {
            auto* cmp = dyn_cast<ICmpInst>(&i);
            if (!cmp) continue;

            const CmpInst::Predicate p = cmp->getPredicate();
            if (!IsOrdinalPred(p)) continue;

            Value* lhs = cmp->getOperand(0);
            Value* rhs = cmp->getOperand(1);

            ConstantInt* ci = dyn_cast<ConstantInt>(rhs);
            Value* v = lhs;
            CmpInst::Predicate effp = p;
            if (!ci)
            {
                ci = dyn_cast<ConstantInt>(lhs);
                if (ci)
                {
                    v = rhs;
                    effp = CmpInst::getSwappedPredicate(p);
                }
            }
            if (!ci) continue;
            if (isa<Constant>(v)) continue;

            if (!v->getType()->isIntegerTy()) continue;
            const unsigned bw = v->getType()->getIntegerBitWidth();
            if (bw != 32 && bw != 64) continue;

            if (ci->isZero()) continue;

            Site s;
            s.Cmp = cmp;
            s.EffectivePred = effp;
            s.V = v;
            s.CBits = ci->getZExtValue();
            s.BitWidth = bw;
            s.IsSigned = IsSignedOrdinal(effp);
            out.push_back(s);
        }
    }
}

static Value* XmmConstFromHash128(IRBuilder<>& b, const Hash128& h)
{
    Type* i64 = b.getInt64Ty();
    return ConstantVector::get({ConstantInt::get(i64, h.Lo), ConstantInt::get(i64, h.Hi)});
}

static Value* EmitMMOForRelation(IRBuilder<>& b, uint64_t sitesalt, unsigned i, Value* vri64, uint8_t rel)
{
    Module* m = b.GetInsertBlock()->getModule();
    LLVMContext& c = b.getContext();
    Type* i64 = Type::getInt64Ty(c);
    Type* xmmt = FixedVectorType::get(i64, 2);

    const uint64_t constpart = sitesalt ^ ((uint64_t)i << 56) ^ ((uint64_t)rel << 40);

    Value* vshl48 = b.CreateShl(vri64, b.getInt64(48), "OrdMMOVshl");
    Value* input = b.CreateXor(vshl48, b.getInt64(constpart), "OrdMMOInput");

    Value* zero128 = Constant::getNullValue(xmmt);
    Value* input128 = b.CreateInsertElement(zero128, input, (uint64_t)0, "OrdMMOInput128");

    Value* kpad128 = XmmConstFromHash128(b, GMMO.Kpad);
    Value* key = b.CreateXor(kpad128, input128, "OrdMMOKey");

    Value* state = XmmConstFromHash128(b, GMMO.Salt);

    // MMOPrimitives.h CompileMMO uses AESENC for rounds 0-2 and AESENCLAST for round 3; using the same intrinsic on the final round would desync precomputed tags from runtime probes
    Function* aesenc = Intrinsic::getDeclaration(m, Intrinsic::x86_aesni_aesenc);
    Function* aesenclast = Intrinsic::getDeclaration(m, Intrinsic::x86_aesni_aesenclast);
    for (int r = 0; r < 4; ++r)
    {
        Value* rk = XmmConstFromHash128(b, GMMO.Rk[r]);
        Value* roundkey = b.CreateXor(rk, key, "OrdMMORkXorKey");
        Function* aes = (r == 3) ? aesenclast : aesenc;
        state = b.CreateCall(aes, {state, roundkey}, "OrdMMOAes");
    }

    Value* salt128 = XmmConstFromHash128(b, GMMO.Salt);
    state = b.CreateXor(state, salt128, "OrdMMOFinal");

    return b.CreateExtractElement(state, (uint64_t)0, "OrdMMOOut");
}

// the x86 backend selects @llvm.x86.aesni.aesenc only when the enclosing fn's target features carries +aes; clang-cl's default x86-64 target-cpu doesn't include it
static void EnsureAesFeatureOnFunction(Function& f)
{
    Attribute existing = f.getFnAttribute("target-features");
    StringRef existingstr = existing.isStringAttribute() ? existing.getValueAsString() : StringRef();
    if (existingstr.contains("+aes")) return;

    SmallString<128> merged;
    if (!existingstr.empty())
    {
        merged = existingstr;
        merged += ",";
    }
    merged += "+aes";
    f.addFnAttr("target-features", merged);
}

static void TransformOrdinalSite(Site& s)
{
    ICmpInst* cmp = s.Cmp;
    Function* f = cmp->getFunction();
    Module* m = f->getParent();
    LLVMContext& c = f->getContext();
    Type* i32 = Type::getInt32Ty(c);
    Type* i64 = Type::getInt64Ty(c);

    EnsureAesFeatureOnFunction(*f);

    const uint64_t signmask = 1ULL << (s.BitWidth - 1);

    IRBuilder<> bpre(cmp);
    Value* v64 = (s.V->getType() == i64) ? s.V : bpre.CreateZExt(s.V, i64, "OrdV64");

    // without the XOR MSB sign fix on signed sites the bit lex block walk disagrees with signed ordering for mixed-sign V vs C
    if (s.IsSigned)
    {
        v64 = bpre.CreateXor(v64, bpre.getInt64(signmask), "OrdV64Sf");
    }

    const uint64_t sitesalt = MMORand64();
    const unsigned bb = 4;
    const unsigned bblocks = s.BitWidth / bb;
    const unsigned vpb = 1u << bb;

    uint64_t kbits = s.CBits;
    if (s.IsSigned) kbits ^= signmask;

    std::vector<uint8_t> kblocks(bblocks);
    for (unsigned i = 0; i < bblocks; ++i)
    {
        const unsigned shift = (bblocks - 1 - i) * bb;
        kblocks[i] = (uint8_t)((kbits >> shift) & (vpb - 1));
    }

    std::vector<uint64_t> tags(bblocks * vpb);
    for (unsigned i = 0; i < bblocks; ++i)
    {
        const uint8_t ki = kblocks[i];
        for (unsigned v = 0; v < vpb; ++v)
        {
            const uint8_t rel = (v < ki) ? 0 : (v == ki) ? 1 : 2;
            const uint64_t input = EncodeMMOInput(sitesalt, (uint8_t)i, (uint8_t)v, rel);
            tags[i * vpb + v] = CompileMMO(input);
        }
    }

    ArrayType* tblt = ArrayType::get(i64, tags.size());
    std::vector<Constant*> tagconsts;
    tagconsts.reserve(tags.size());
    for (uint64_t t : tags) tagconsts.push_back(ConstantInt::get(i64, t));
    Constant* tblinit = ConstantArray::get(tblt, tagconsts);
    const std::string tblname = "OrdHashTbl" + std::to_string(SiteCounter);
    GlobalVariable* tblgv = new GlobalVariable(*m, tblt, true, GlobalValue::PrivateLinkage, tblinit, tblname);
    tblgv->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    tblgv->setAlignment(Align(16));

    BasicBlock* cmpbb = cmp->getParent();
    BasicBlock* tail = cmpbb->splitBasicBlock(cmp, "OrdTail");
    cmpbb->getTerminator()->eraseFromParent();

    BasicBlock* verdictlt = BasicBlock::Create(c, "OrdVerdictLt", f);
    BasicBlock* verdicteq = BasicBlock::Create(c, "OrdVerdictEq", f);
    BasicBlock* verdictgt = BasicBlock::Create(c, "OrdVerdictGt", f);

    std::vector<BasicBlock*> blkbbs(bblocks);
    std::vector<BasicBlock*> tryeqbbs(bblocks);
    for (unsigned i = 0; i < bblocks; ++i)
    {
        blkbbs[i] = BasicBlock::Create(c, "OrdBlk" + std::to_string(i), f);
        tryeqbbs[i] = BasicBlock::Create(c, "OrdTryEq" + std::to_string(i), f);
    }

    IRBuilder<>(cmpbb).CreateBr(blkbbs[0]);

    for (unsigned i = 0; i < bblocks; ++i)
    {
        IRBuilder<> bi(blkbbs[i]);

        const unsigned shift = (bblocks - 1 - i) * bb;
        Value* shifted = shift ? bi.CreateLShr(v64, bi.getInt64(shift), "OrdShr") : v64;
        Value* vr = bi.CreateAnd(shifted, bi.getInt64(vpb - 1), "OrdVr");

        Value* fullidx = bi.CreateAdd(bi.getInt64((uint64_t)i * vpb), vr, "OrdIdx");
        Value* gep = bi.CreateInBoundsGEP(i64, tblgv, fullidx, "OrdGep");
        Value* lookup = bi.CreateAlignedLoad(i64, gep, Align(8), "OrdLookup");

        Value* ltprobe = EmitMMOForRelation(bi, sitesalt, i, vr, 0);
        Value* ltmatch = bi.CreateICmpEQ(ltprobe, lookup, "OrdLtMatch");
        bi.CreateCondBr(ltmatch, verdictlt, tryeqbbs[i]);

        IRBuilder<> bt(tryeqbbs[i]);
        Value* eqprobe = EmitMMOForRelation(bt, sitesalt, i, vr, 1);
        Value* eqmatch = bt.CreateICmpEQ(eqprobe, lookup, "OrdEqMatch");
        BasicBlock* oneq = (i + 1 < bblocks) ? blkbbs[i + 1] : verdicteq;
        bt.CreateCondBr(eqmatch, oneq, verdictgt);
    }

    IRBuilder<>(verdictlt).CreateBr(tail);
    IRBuilder<>(verdicteq).CreateBr(tail);
    IRBuilder<>(verdictgt).CreateBr(tail);

    IRBuilder<> bp(tail, tail->begin());
    PHINode* verdict = bp.CreatePHI(i32, 3, "OrdVerdict");
    verdict->addIncoming(ConstantInt::getSigned(i32, -1), verdictlt);
    verdict->addIncoming(ConstantInt::get(i32, 0), verdicteq);
    verdict->addIncoming(ConstantInt::get(i32, 1), verdictgt);

    IRBuilder<> bc(cmp);
    Value* newcmp = bc.CreateICmp(FinalPredFor(s.EffectivePred), verdict, ConstantInt::get(i32, 0), "OrdFinal");
    cmp->replaceAllUsesWith(newcmp);
    cmp->eraseFromParent();

    ++SiteCounter;
}

static void ProcessFunction(Function& f)
{
    if (f.isDeclaration()) return;
    if (f.getName().starts_with("OrdHash")) return;
    if (HasNoObfuscateAnnotation(f)) return;

    std::vector<Site> sites;
    CollectSites(f, sites);

    for (Site& s : sites)
    {
        if (IsOrdinalPred(s.EffectivePred)) TransformOrdinalSite(s);
    }
}

bool RunOrdinalHash(Module& m)
{
    if (!OrdHashEnable) return false;

    SiteCounter = 0;
    MMOInit();

    for (Function& f : m) ProcessFunction(f);

    return SiteCounter > 0;
}

PreservedAnalyses OrdinalHashPass::run(Module& m, ModuleAnalysisManager&)
{
    if (!RunOrdinalHash(m)) return PreservedAnalyses::all();
    return PreservedAnalyses::none();
}