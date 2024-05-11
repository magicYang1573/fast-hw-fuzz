package fuzzing.fast

import firrtl.AnnotationSeq
import firrtl.annotations.{CircuitTarget, NoTargetAnnotation}
import firrtl.options.{Dependency, DuplicateHandling, ExceptOnError, ShellOption}
import firrtl.stage.{FirrtlFileAnnotation, RunFirrtlTransformAnnotation}
import scopt.OptionParser
import chiseltest.WriteVcdAnnotation
import fuzzing.coverage.DoNotCoverAnnotation

case class Harness(name: String) extends NoTargetAnnotation
case class FeedbackCap(cap: Int) extends NoTargetAnnotation
case class OutputFolder(str: String) extends NoTargetAnnotation
case class SeedInputFolder(str: String) extends NoTargetAnnotation
case class ThreadNum(num: Int) extends NoTargetAnnotation
case class MuxToggleOpAnnotation(fullToggle: Boolean) extends NoTargetAnnotation


//Note: Currently doesn't extend native argument parser, may be useful later.
class FuzzingArgumentParser extends OptionParser[AnnotationSeq]("fuzzer") with DuplicateHandling with ExceptOnError {

  private val argumentOptions = Seq(
    new ShellOption[String](
      longOption = "FIRRTL",
      toAnnotationSeq = input => Seq(FirrtlFileAnnotation(input)),
      helpText = "",
      helpValueName = Some("<str>")
    ),
    new ShellOption[String](
      longOption = "Harness",
      toAnnotationSeq = input => Seq(Harness(input)),
      helpText = "",
      helpValueName = Some("<str>")
    ),
    new ShellOption[Unit](
      longOption = "Directed",
//       toAnnotationSeq = _ => Seq(DoNotCoverAnnotation(CircuitTarget("TLI2C").module("TLMonitor_72")),
//                                   DoNotCoverAnnotation(CircuitTarget("TLI2C").module("DummyPlusArgReader_75")),
//                                   DoNotCoverAnnotation(CircuitTarget("TLSPI").module("TLMonitor_66")),
//                                   DoNotCoverAnnotation(CircuitTarget("TLSPI").module("SPIFIFO_1")),
//                                   DoNotCoverAnnotation(CircuitTarget("TLSPI").module("SPIMedia_1")),
//                                   DoNotCoverAnnotation(CircuitTarget("TLSPI").module("DummyPlusArgReader_69")),
// //                                  DoNotCoverAnnotation(CircuitTarget("TLSPI").module("Queue_18")),
// //                                  DoNotCoverAnnotation(CircuitTarget("TLSPI").module("Queue_19")),
//                                   DoNotCoverAnnotation(CircuitTarget("TLSPI").module("SPIPhysical_1")),

//                                   DoNotCoverAnnotation(CircuitTarget("Sodor1Stage").module("DebugModule")),
//                                   DoNotCoverAnnotation(CircuitTarget("Sodor1Stage").module("AsyncReadMem")),
//                                   DoNotCoverAnnotation(CircuitTarget("Sodor1Stage").module("AsyncScratchPadMemory")),
                                  
//                                   DoNotCoverAnnotation(CircuitTarget("Sodor3Stage").module("DebugModule")),
//                                   DoNotCoverAnnotation(CircuitTarget("Sodor3Stage").module("SyncScratchPadMemory")),
//                                   DoNotCoverAnnotation(CircuitTarget("Sodor3Stage").module("SyncMem")),

//                                   DoNotCoverAnnotation(CircuitTarget("Sodor5Stage").module("RegisterFile")),
//                                   DoNotCoverAnnotation(CircuitTarget("Sodor5Stage").module("DebugModule")),
//                                   DoNotCoverAnnotation(CircuitTarget("Sodor5Stage").module("AsyncReadMem")),
//                                   DoNotCoverAnnotation(CircuitTarget("Sodor5Stage").module("AsyncScratchPadMemory")),

//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("TLMonitor_35")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("TLXbar_tlMasterXbar")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("Arbiter_9")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("ICache_icache")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("Frontend_frontend")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("PTW")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("TLMonitor_34")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("TLMonitor_36")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("TLBuffer_SystemBus")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("CSRFile")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("FPU")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("Rocket")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("NonBlockingDCache_dcache")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("Arbiter_7")),
//                                   DoNotCoverAnnotation(CircuitTarget("RocketTile").module("metaReadArb")),
//       ),
      helpText = ""
    ),
    new ShellOption[Unit](
      longOption = "VCD",
      toAnnotationSeq = _ => Seq(WriteVcdAnnotation),
      helpText = "",
    ),
    new ShellOption[Int](
      longOption = "Feedback",
      toAnnotationSeq = input => Seq(FeedbackCap(input)),
      helpText = "",
      helpValueName = Some("<i>")
    ),
    new ShellOption[Int](
      longOption = "ThreadNum",
      toAnnotationSeq = input => Seq(ThreadNum(input)),
      helpText = "",
      helpValueName = Some("<i>")
    ),
    new ShellOption[Unit](
      longOption = "mux-toggle-coverage",
      toAnnotationSeq = _ =>
        Seq(
          RunFirrtlTransformAnnotation(Dependency(fuzzing.pass.MuxToggleCoverage)),
          MuxToggleOpAnnotation(fullToggle = false)
        ),
      helpText = "enable mux toggle coverage instrumentation"
    ),
    new ShellOption[Unit](
      longOption = "full-mux-toggle-coverage",
      toAnnotationSeq = _ =>
        Seq(
          RunFirrtlTransformAnnotation(Dependency(fuzzing.pass.MuxToggleCoverage)),
          MuxToggleOpAnnotation(fullToggle = true)
        ),
      helpText = "enable full mux toggle instrumentation"
    ),
    new ShellOption[Unit](
      longOption = "line-coverage",
      toAnnotationSeq = _ =>
        Seq(
          RunFirrtlTransformAnnotation(Dependency(fuzzing.coverage.LineCoveragePass))
        ),
      helpText = "enable line coverage instrumentation"
    ),
    new ShellOption[String](
      longOption = "OutputFolder",
      toAnnotationSeq = input => Seq(OutputFolder(input)),
      helpText = "",
      helpValueName = Some("<str>")
    ),
    new ShellOption[String](
      longOption = "SeedInputFolder",
      toAnnotationSeq = input => Seq(SeedInputFolder(input)),
      helpText = "",
      helpValueName = Some("<str>")
    ),
  )

  argumentOptions.foreach(_.addOption(this))
  this.help("help").text("prints this usage text")
}
