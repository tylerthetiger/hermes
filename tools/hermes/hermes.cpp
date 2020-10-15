/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "hermes/CompilerDriver/CompilerDriver.h"
#include "hermes/ConsoleHost/ConsoleHost.h"
#include "hermes/ConsoleHost/RuntimeFlags.h"
#include "hermes/Support/OSCompat.h"
#include "hermes/Support/PageAccessTracker.h"

#include "llvh/ADT/SmallString.h"
#include "llvh/ADT/SmallVector.h"
#include "llvh/Support/Allocator.h"
#include "llvh/Support/CommandLine.h"
#include "llvh/Support/FileSystem.h"
#include "llvh/Support/InitLLVM.h"
#include "llvh/Support/PrettyStackTrace.h"
#include "llvh/Support/Program.h"
#include "llvh/Support/SHA1.h"
#include "llvh/Support/Signals.h"

#include "repl.h"

// SanitzerCoverage-based coverage collection code for libcoverage.
// Copy+paste this code into the JavaScript shell binary.

//
// BEGIN FUZZING CODE
//
       #include <sys/types.h>
       #include <sys/stat.h>
       #include <fcntl.h>
#include <sys/mman.h>
#define REPRL_CRFD 100
#define REPRL_CWFD 101
#define REPRL_DRFD 102
#define REPRL_DWFD 103

#define SHM_SIZE 0x100000
#define MAX_EDGES ((SHM_SIZE - 4) * 8)

#define CHECK(cond) if (!(cond)) { fprintf(stderr, "\"" #cond "\" failed\n"); _exit(-1); }

struct shmem_data {
    uint32_t num_edges;
    unsigned char edges[];
};

struct shmem_data* __shmem;
uint32_t *__edges_start, *__edges_stop;

void __sanitizer_cov_reset_edgeguards() {
    uint64_t N = 0;
    for (uint32_t *x = __edges_start; x < __edges_stop && N < MAX_EDGES; x++)
        *x = ++N;
}

extern "C" void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    // Avoid duplicate initialization
    if (start == stop || *start)
        return;

    if (__edges_start != NULL || __edges_stop != NULL) {
        fprintf(stderr, "Coverage instrumentation is only supported for a single module\n");
        _exit(-1);
    }

    __edges_start = start;
    __edges_stop = stop;

    // Map the shared memory region
    const char* shm_key = getenv("SHM_ID");
    if (!shm_key) {
        puts("[COV] no shared memory bitmap available, skipping");
        __shmem = (struct shmem_data*) malloc(SHM_SIZE);
    } else {
        int fd = shm_open(shm_key, O_RDWR, S_IREAD | S_IWRITE);
        if (fd <= -1) {
            fprintf(stderr, "Failed to open shared memory region: %s\n", strerror(errno));
            _exit(-1);
        }

        __shmem = (struct shmem_data*) mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (__shmem == MAP_FAILED) {
            fprintf(stderr, "Failed to mmap shared memory region\n");
            _exit(-1);
        }
    }

    __sanitizer_cov_reset_edgeguards();

    __shmem->num_edges = stop - start;
    printf("[COV] edge counters initialized. Shared memory: %s with %u edges\n", shm_key, __shmem->num_edges);
}

extern "C" void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    // There's a small race condition here: if this function executes in two threads for the same
    // edge at the same time, the first thread might disable the edge (by setting the guard to zero)
    // before the second thread fetches the guard value (and thus the index). However, our
    // instrumentation ignores the first edge (see libcoverage.c) and so the race is unproblematic.
    uint32_t index = *guard;
    // If this function is called before coverage instrumentation is properly initialized we want to return early.
    if (!index) return;
    __shmem->edges[index / 8] |= 1 << (index % 8);
    *guard = 0;
}

//
// END FUZZING CODE
//
using namespace hermes;

namespace cl {
using llvh::cl::opt;

static opt<bool> EnableJIT(
    "jit",
    llvh::cl::desc("enable JIT compilation"),
    llvh::cl::init(false));

static opt<bool> DumpJITCode(
    "dump-jitcode",
    llvh::cl::desc("dump JIT'ed code"),
    llvh::cl::init(false));

static opt<bool> JITCrashOnError(
    "jit-crash-on-error",
    llvh::cl::desc("crash on any JIT compilation error"),
    llvh::cl::init(false));

static opt<unsigned> Repeat(
    "Xrepeat",
    llvh::cl::desc("Repeat execution N number of times"),
    llvh::cl::init(1),
    llvh::cl::Hidden);

static opt<bool> RandomizeMemoryLayout(
    "Xrandomize-memory-layout",
    llvh::cl::desc("Randomize stack placement etc."),
    llvh::cl::init(false),
    llvh::cl::Hidden);

static opt<bool> GCAllocYoung(
    "gc-alloc-young",
    desc("Determines whether to (initially) allocate in the young generation"),
    cat(GCCategory),
    init(true));

static opt<bool> GCRevertToYGAtTTI(
    "gc-revert-to-yg-at-tti",
    desc("Determines whether to revert to young generation, if necessary, at "
         "TTI notification"),
    cat(GCCategory),
    init(false));

static opt<bool> GCBeforeStats(
    "gc-before-stats",
    desc("Perform a full GC just before printing statistics at exit"),
    cat(GCCategory),
    init(false));

static opt<bool> GCPrintStats(
    "gc-print-stats",
    desc("Output summary garbage collection statistics at exit"),
    cat(GCCategory),
    init(false));

static opt<unsigned> ExecutionTimeLimit(
    "time-limit",
    llvh::cl::desc("Number of milliseconds after which to abort JS exeuction"),
    llvh::cl::init(0));
} // namespace cl

/// Execute Hermes bytecode \p bytecode, respecting command line arguments.
/// \return an exit status.
static int executeHBCBytecodeFromCL(
    std::unique_ptr<hbc::BCProvider> bytecode,
    const driver::BytecodeBufferInfo &info) {
  auto recStats =
      (cl::GCPrintStats || cl::GCBeforeStats) && !cl::StableInstructionCount;
  ExecuteOptions options;
  options.runtimeConfig =
      vm::RuntimeConfig::Builder()
          .withGCConfig(
              vm::GCConfig::Builder()
                  .withMinHeapSize(cl::MinHeapSize.bytes)
                  .withInitHeapSize(cl::InitHeapSize.bytes)
                  .withMaxHeapSize(cl::MaxHeapSize.bytes)
                  .withOccupancyTarget(cl::OccupancyTarget)
                  .withSanitizeConfig(
                      vm::GCSanitizeConfig::Builder()
                          .withSanitizeRate(cl::GCSanitizeRate)
                          .withRandomSeed(cl::GCSanitizeRandomSeed)
                          .build())
                  .withShouldRandomizeAllocSpace(cl::GCRandomizeAllocSpace)
                  .withShouldRecordStats(recStats)
                  .withShouldReleaseUnused(vm::kReleaseUnusedNone)
                  .withAllocInYoung(cl::GCAllocYoung)
                  .withRevertToYGAtTTI(cl::GCRevertToYGAtTTI)
                  .build())
          .withEnableJIT(cl::DumpJITCode || cl::EnableJIT)
          .withEnableEval(cl::EnableEval)
          .withVerifyEvalIR(cl::VerifyIR)
          .withOptimizedEval(cl::OptimizedEval)
          .withVMExperimentFlags(cl::VMExperimentFlags)
          .withES6Proxy(cl::ES6Proxy)
          .withES6Symbol(cl::ES6Symbol)
          .withEnableSampleProfiling(cl::SampleProfiling)
          .withRandomizeMemoryLayout(cl::RandomizeMemoryLayout)
          .withTrackIO(cl::TrackBytecodeIO)
          .withEnableHermesInternal(cl::EnableHermesInternal)
          .withEnableHermesInternalTestMethods(
              cl::EnableHermesInternalTestMethods)
          .withAllowFunctionToStringWithRuntimeSource(cl::AllowFunctionToString)
          .build();

  options.basicBlockProfiling = cl::BasicBlockProfiling;

  options.stopAfterInit = false;
#ifdef HERMESVM_PROFILER_EXTERN
  options.patchProfilerSymbols = cl::PatchProfilerSymbols;
  options.profilerSymbolsFile = cl::ProfilerSymbolsFile;
#endif
  options.timeLimit = cl::ExecutionTimeLimit;
  options.dumpJITCode = cl::DumpJITCode;
  options.jitCrashOnError = cl::JITCrashOnError;
  options.stopAfterInit = cl::StopAfterInit;
  options.forceGCBeforeStats = cl::GCBeforeStats;
  options.stabilizeInstructionCount = cl::StableInstructionCount;
#ifdef HERMESVM_SERIALIZE
  options.SerializeAfterInitFile = cl::SerializeAfterInitFile;
  options.DeserializeFile = cl::DeserializeFile;
  options.SerializeVMPath = cl::SerializeVMPath;
#endif

  bool success;
  if (cl::Repeat <= 1) {
    success = executeHBCBytecode(std::move(bytecode), options, &info.filename);
  } else {
    // The runtime is supposed to own the bytecode exclusively, but we
    // want to keep it around in this special case, so we can reuse it
    // between iterations.
    std::shared_ptr<hbc::BCProvider> sharedBytecode = std::move(bytecode);

    success = true;
    for (unsigned i = 0; i < cl::Repeat; ++i) {
      success &= executeHBCBytecode(
          std::shared_ptr<hbc::BCProvider>{sharedBytecode},
          options,
          &info.filename);
    }
  }
  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}

static vm::RuntimeConfig getReplRuntimeConfig() {
  return vm::RuntimeConfig::Builder()
      .withGCConfig(
          vm::GCConfig::Builder()
              .withInitHeapSize(cl::InitHeapSize.bytes)
              .withMaxHeapSize(cl::MaxHeapSize.bytes)
              .withSanitizeConfig(vm::GCSanitizeConfig::Builder()
                                      .withSanitizeRate(cl::GCSanitizeRate)
                                      .withRandomSeed(cl::GCSanitizeRandomSeed)
                                      .build())
              .withShouldRecordStats(cl::GCPrintStats)
              .build())
      .withES6Proxy(cl::ES6Proxy)
      .withES6Symbol(cl::ES6Symbol)
      .withEnableHermesInternal(true)
      .withEnableHermesInternalTestMethods(true)
      .withAllowFunctionToStringWithRuntimeSource(cl::AllowFunctionToString)
      .build();
}

int main(int argc, char **argv) {
#ifndef HERMES_FBCODE_BUILD
  // Normalize the arg vector.
  llvh::InitLLVM initLLVM(argc, argv);
#else
  // When both HERMES_FBCODE_BUILD and sanitizers are enabled, InitLLVM may have
  // been already created and destroyed before main() is invoked. This presents
  // a problem because InitLLVM can't be instantiated more than once in the same
  // process. The most important functionality InitLLVM provides is shutting
  // down LLVM in its destructor. We can use "llvm_shutdown_obj" to do the same.
  llvh::llvm_shutdown_obj Y;
#endif

  llvh::cl::AddExtraVersionPrinter(driver::printHermesCompilerVMVersion);
  llvh::cl::ParseCommandLineOptions(argc, argv, "Hermes driver\n");

  if (cl::InputFilenames.size() == 0) {
    return repl(getReplRuntimeConfig());
  }

  // Tell compiler to emit async break check if time-limit feature is enabled
  // so that user can turn on this feature with single ExecutionTimeLimit
  // option.
  if (cl::ExecutionTimeLimit > 0) {
    cl::EmitAsyncBreakCheck = true;
  }

  // Make sure any allocated alt signal stack is not considered a leak
  // by ASAN.
  oscompat::SigAltStackLeakSuppressor sigAltLeakSuppressor;
  driver::CompileResult res = driver::compileFromCommandLineOptions();
  if (res.bytecodeProvider) {
    auto ret = executeHBCBytecodeFromCL(
        std::move(res.bytecodeProvider), res.bytecodeBufferInfo);
    return ret;
  } else {
    return res.status;
  }
}
