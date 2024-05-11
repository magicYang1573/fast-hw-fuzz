/*
 * Copyright (c) 2017-2021 The Regents of the University of California
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package fuzzing.fast

import fuzzing.targets.{FIRRTLHandler, FuzzTarget}
import java.io.{File, InputStream, OutputStream, PrintWriter}
import java.io.ByteArrayInputStream
import java.util.concurrent.{Executors, Future, Callable}
import java.io.File
import java.time.Duration
import scala.util.Random
import scala.collection.JavaConverters
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ForkJoinPool

import fuzzing.fast.util.GuidanceException
import fuzzing.fast.util.IOUtils
import fuzzing.fast.util.Coverage

// import com.google.common.util.concurrent.ThreadFactoryBuilder
// import net.openhft.affinity.AffinityThreadFactory
// import net.openhft.affinity.AffinityStrategies._
// import java.lang.Thread
// import java.lang.management.ManagementFactory
// import scala.sys.process._

/** Provides a main function that can be used to interface with the AFL fuzzer.
 *
 *  Based on code written by Rohan Padhye and Caroline Lemieux for the JQF project
 */
object FastDriver extends App {
    val parser = new FuzzingArgumentParser
    val argAnnos = parser.parse(args, Seq()).get

    // Parse args
    val targetKind = argAnnos.collectFirst {case Harness(i) => i}.getOrElse("")
    val feedbackCap = argAnnos.collectFirst {case FeedbackCap(i) => i}.getOrElse(0)
    val outputFolder_str = argAnnos.collectFirst {case OutputFolder(i) => i}.getOrElse("")
    val seedInputFolder_str = argAnnos.collectFirst {case SeedInputFolder(i) => i}.getOrElse("")
    val threadNum = argAnnos.collectFirst {case ThreadNum(i) => i}.getOrElse(2)
  
    val targets: Array[FuzzTarget] = (for(i <- 1 to threadNum) yield {
    	FIRRTLHandler.firrtlToTarget(targetKind, "test_run_dir/fast_fuzz_" + targetKind + "_" + i, argAnnos)
    }).toArray

    val testName = "test_run_dir/fast_fuzz_" + targetKind
    val duration: Duration = Duration.ofHours(1)  // or null for unlimited time
    val trials: Long = 100L  // or null for unlimited trials
    val outputDir: File = new File(outputFolder_str)
    val seedInputDir: File = new File(seedInputFolder_str)

    val fuzzGuidance = new FuzzGuidance(testName, duration, trials, outputDir, seedInputDir)

    println("\nReady to fast fuzz! ")

    FastFuzz.fuzz(targets, fuzzGuidance, feedbackCap)
}

object FastFuzz {

    var cumulativeCoverage = 0.0 //0-100%
    var coverPointsNum = 0 //total coverPoints number
    var cycleSum = 0 : Long
    var totalSimTime = 0: Long
    var totalGetTime = 0: Long
    var totalUpdTime = 0: Long
    var totalSyncTime= 0: Long
    val logFile = new PrintWriter(new File("cov.log"))

    // The Fuzz Loop
    def fuzz(targets: Array[FuzzTarget], fuzzGuidance: FuzzGuidance, feedbackCap: Int) : Unit = {
        val threadNum = targets.length
        val pipeline = true
        // val pipeline = false
        val iterNum = 100000    // draft version, set iteration time manually
        // val iterNum = 1 //debug
        val startTime = System.nanoTime()
        // /*
        if(threadNum == 1) {
            for(iter <- 1 to iterNum) { //iteration
                // 1. Get input
                val get_t1 = System.nanoTime()
                val input = fuzzGuidance.getInput()
                val in_stream = fuzzGuidance.createParameterStream(input)
                val get_t2 = System.nanoTime()
                totalGetTime += (get_t2 - get_t1) / 1000

            	// 2. Run simulation
            	//feedbackCap：limite the max value of coverPoints hit count to 255
                val sim_t1 = System.nanoTime()
            	val (coverage0, isValid, cycleNum) = targets(0).run(in_stream, feedbackCap)
                val sim_t2 = System.nanoTime()

            	in_stream.close()
                
                // 3. Update seed corpus
                val upd_t1 = System.nanoTime()
                val runCov = new Coverage(coverage0.toArray) //get the byte sequence
            	input.coverage = runCov
                input.isValid = isValid
                fuzzGuidance.updateSeedCorpus(input) //little time used

            	// 4. Count stastics
            	cycleSum = cycleNum
                totalSimTime += (sim_t2 - sim_t1) / 1000
                if(coverPointsNum == 0)
                	coverPointsNum = coverage0.size
            	// overallCoverage = overallCoverage.union(coverage0.zipWithIndex.filter(_._1 != 0).map(_._2).toSet)
                // if(overallCoverage.size != fuzzGuidance.getMaxCoverage()) {
                //     println("Error") // debug
                //     println(s"${overallCoverage.size} != ${fuzzGuidance.getMaxCoverage()}")
                // }
                // val thisCoverage = overallCoverage.size.toDouble / coverPointsNum
                val thisCoverage = fuzzGuidance.getMaxCoverage().toDouble / coverPointsNum
                if(thisCoverage > cumulativeCoverage) {                                            
                    cumulativeCoverage = thisCoverage // update coverage
                    val time = (System.nanoTime()-startTime) / 1000 / 1000 / 1000   
                    logFile.println(s"$cumulativeCoverage, $cycleSum, $time")
                }
                val upd_t2 = System.nanoTime()
                totalUpdTime += (upd_t2 - upd_t1) / 1000

            } //end iteration
            val time = (System.nanoTime()-startTime) / 1000 / 1000 / 1000   
            logFile.println(s"$cumulativeCoverage, $cycleSum, $time")
        } else if(pipeline) { // */
            // val executor = Executors.newFixedThreadPool(threadNum,
            //     new AffinityThreadFactory("bg", DIFFERENT_CORE, DIFFERENT_SOCKET, ANY)) // build thread pool
            // val executor = Executors.newFixedThreadPool(threadNum)
            // val executor = new ForkJoinPool()
            val executor = new ForkJoinPool(threadNum)
            val cycleNums: Array[Array[Long]] = Array.ofDim[Long](2, threadNum)
            val simTimes:  Array[Array[Long]] = Array.ofDim[Long](2, threadNum)
            // val inputs: Array[Array[LinearInput]] = Array.ofDim[LinearInput](2, threadNum) //ping-pong buffer
            val inputs = fuzzGuidance.getInputs(2, threadNum) //ping-pong buffer
            var tag: Int = 1 //point to current input
            //use pipeline to overlap
            try {
                for(iter <- 1 to iterNum) { //iteration
                    if(iter == 1) {
                        for(idx <- 0 until threadNum) {
                            inputs(0)(idx) = fuzzGuidance.getInput()
                        }
                    }
                    tag = tag ^ 1
                    val futures: Array[Future[_]] = targets.zip(inputs(tag)).zipWithIndex.map { case ((target, input), idx) =>
                    executor.submit(new Runnable {
                	    def run() {
                            // val input_new = fuzzGuidance.getCopyInput(input)
                            val in_stream = fuzzGuidance.createParameterStream(input)
                  		    // 2. Run simulation
                            val sim_t1 = System.nanoTime()
                  		    val (coverage0, isValid, cycleNum) = target.run(in_stream, feedbackCap)
                            val sim_t2 = System.nanoTime()

                  		    in_stream.close()

                            // 3. Update seed corpus(1)
                            val runCov = new Coverage(coverage0.toArray)
                  		    input.coverage = runCov
                            input.isValid = isValid

                            // 4. Count Stastics(1)
                            cycleNums(tag)(idx) = cycleNum
                            simTimes(tag)(idx)  = (sim_t2 - sim_t1) / 1000
                        }
                    }) //end executor
                    } //end futures

                    if(iter != 1) {
                        val upd_t1 = System.nanoTime()
                        // 3. Update seed corpus(2) of previous iteration
                        for(idx <- 0 until threadNum) {
                            fuzzGuidance.updateSeedCorpus(inputs(tag^1)(idx)) //little time used
                        }

                        // 4. Count Stastics(2) of previous iteration
                        cycleSum = 0
                        for(idx <- 0 until threadNum) {
                            cycleSum += cycleNums(tag^1)(idx)
                            totalSimTime += simTimes(tag^1)(idx)
                        }
                        if(coverPointsNum == 0) {
                            val coverage = inputs(tag^1)(0).coverage.getCoverPoints()
                            coverPointsNum = coverage.size
                        }
                        // for(idx <- 0 until threadNum) {
                        //     val coverage = inputs(tag^1)(idx).coverage.getCoverPoints()
                        //     overallCoverage = overallCoverage.union(coverage.zipWithIndex.filter(_._1 != 0).map(_._2).toSet)
                	    //     coverPointsNum = coverage.size
                        // }
                        // if(overallCoverage.size != fuzzGuidance.getMaxCoverage()) {
                        //     println("Error") // debug
                        //     println(s"${overallCoverage.size} != ${fuzzGuidance.getMaxCoverage()}")
                        // }
                        // val thisCoverage = overallCoverage.size.toDouble / coverPointsNum
                        val thisCoverage = fuzzGuidance.getMaxCoverage().toDouble / coverPointsNum
                        if(thisCoverage > cumulativeCoverage) {                                            
                            cumulativeCoverage = thisCoverage //update coverage
                            val time = (System.nanoTime()-startTime) / 1000 / 1000 / 1000   
                            logFile.println(s"$cumulativeCoverage, $cycleSum, $time")
                        }

                        val upd_t2 = System.nanoTime()
                        // println(s"upd time: ${(upd_t2-upd_t1) / 1000 }vs")
                        totalUpdTime += (upd_t2 - upd_t1) / 1000
                    }

                    // 1. Get input for next iteration
                    val get_t1 = System.nanoTime()
                    for(idx <- 0 until threadNum) {
                        inputs(tag^1)(idx) = fuzzGuidance.getInput()
                    }
                    val get_t2 = System.nanoTime()
                    // println(s"get time: ${(get_t2-get_t1) / 1000 }vs")
                    totalGetTime += (get_t2 - get_t1) / 1000

                    // Wait for all tasks to complete before moving to the next iteration
                    val sync_t1 = System.nanoTime()
                    futures.foreach(_.get()) //latest end time - earliest start time
                    //pure sync time = latest end time - earliest end time
                    val sync_t2 = System.nanoTime()
                    // println(s"sync time: ${(sync_t2-sync_t1) / 1000 }vs")
                    totalSyncTime += (sync_t2 - sync_t1) / 1000

                    if(iter == iterNum) {
                        // tag = tag ^ 1
                        for(idx <- 0 until threadNum) {
                            fuzzGuidance.updateSeedCorpus(inputs(tag)(idx)) //little time used
                        }

                        cycleSum = 0
                        for(idx <- 0 until threadNum) {
                            cycleSum += cycleNums(tag)(idx)
                            totalSimTime += simTimes(tag)(idx)
                        }
                        if(coverPointsNum == 0) {
                            val coverage = inputs(tag)(0).coverage.getCoverPoints()
                            coverPointsNum = coverage.size
                        }
                        // for(idx <- 0 until threadNum) {
                        //     val coverage = inputs(tag)(idx).coverage.getCoverPoints()
                        //     overallCoverage = overallCoverage.union(coverage.zipWithIndex.filter(_._1 != 0).map(_._2).toSet)
                	    //     coverPointsNum = coverage.size
                        // }
                        // if(overallCoverage.size != fuzzGuidance.getMaxCoverage()) {
                        //     println("Error") // debug
                        //     println(s"${overallCoverage.size} != ${fuzzGuidance.getMaxCoverage()}")
                        // }
                        // val thisCoverage = overallCoverage.size.toDouble / coverPointsNum
                        val thisCoverage = fuzzGuidance.getMaxCoverage().toDouble / coverPointsNum
                        if(thisCoverage > cumulativeCoverage) {                                            
                            cumulativeCoverage = thisCoverage //update coverage
                            val time = (System.nanoTime()-startTime) / 1000 / 1000 / 1000   
                            logFile.println(s"$cumulativeCoverage, $cycleSum, $time")
                        }
                    }
                } //end iteration
                val time = (System.nanoTime()-startTime) / 1000 / 1000 / 1000   
                logFile.println(s"$cumulativeCoverage, $cycleSum, $time")
            } catch {
                case _: java.io.IOException =>
            } finally {
                executor.shutdown()
            }
        } else {
            val executor = new ForkJoinPool(threadNum)
            val cycleNums = new Array[Long](threadNum)
            val simTimes  = new Array[Long](threadNum)
            val inputs = fuzzGuidance.getInputs(1, threadNum)
            try {
                for(iter <- 1 to iterNum) { //iteration
                    // 1. Get input
                    val get_t1 = System.nanoTime()
                    for(idx <- 0 until threadNum) {
                        inputs(0)(idx) = fuzzGuidance.getInput()
                    }
                    val get_t2 = System.nanoTime()
                    totalGetTime += (get_t2 - get_t1) / 1000

                    val futures: Array[Future[_]] = targets.zip(inputs(0)).zipWithIndex.map { case ((target, input), idx) =>
                    executor.submit(new Runnable {
                	    def run() {
                            val in_stream = fuzzGuidance.createParameterStream(input)
                  		    // 2. Run simulation
                            val sim_t1 = System.nanoTime()
                  		    val (coverage0, isValid, cycleNum) = target.run(in_stream, feedbackCap)
                            val sim_t2 = System.nanoTime()

                  		    in_stream.close()

                            // 3. Update seed corpus(1)
                            val runCov = new Coverage(coverage0.toArray)
                  		    input.coverage = runCov
                            input.isValid = isValid

                            // 4. Count Stastics(1)
                            cycleNums(idx) = cycleNum
                            simTimes(idx)  = (sim_t2 - sim_t1) / 1000
                        }
                    }) //end executor
                    } //end futures

                    // Wait for all tasks to complete before moving to the next iteration
                    val sync_t1 = System.nanoTime()
                    futures.foreach(_.get()) //latest end time - earliest start time
                    //pure sync time = latest end time - earliest end time
                    val sync_t2 = System.nanoTime()
                    totalSyncTime += (sync_t2 - sync_t1) / 1000

                    val upd_t1 = System.nanoTime()
                    // 3. Update seed corpus(2)
                    for(idx <- 0 until threadNum) {
                        fuzzGuidance.updateSeedCorpus(inputs(0)(idx)) //little time used
                    }
                    // 4. Count Stastics(2)
                    cycleSum = 0
                    for(idx <- 0 until threadNum) {
                        cycleSum += cycleNums(idx)
                        totalSimTime += simTimes(idx)
                    }
                    if(coverPointsNum == 0) {
                        val coverage = inputs(0)(0).coverage.getCoverPoints()
                        coverPointsNum = coverage.size
                    }
                    val thisCoverage = fuzzGuidance.getMaxCoverage().toDouble / coverPointsNum
                    if(thisCoverage > cumulativeCoverage) {                                            
                        cumulativeCoverage = thisCoverage //update coverage
                        val time = (System.nanoTime()-startTime) / 1000 / 1000 / 1000   
                        logFile.println(s"$cumulativeCoverage, $cycleSum, $time")
                    }
                    val upd_t2 = System.nanoTime()
                    totalUpdTime += (upd_t2 - upd_t1) / 1000
                } //end iteration
                val time = (System.nanoTime()-startTime) / 1000 / 1000 / 1000   
                logFile.println(s"$cumulativeCoverage, $cycleSum, $time")
            } catch {
                case _: java.io.IOException =>
            } finally {
                executor.shutdown()
            }
        } //end else

        val endTime = System.nanoTime()
        println(s"Total Time: ${(endTime-startTime) / 1000 / 1000}ms")
        println(s"Avg SimTime: ${totalSimTime / threadNum / iterNum}vs")
        println(s"Avg GetTime: ${totalGetTime / iterNum}vs")
        println(s"Avg UpdTime: ${totalUpdTime / iterNum}vs")
        println(s"Avg SyncTime:${totalSyncTime/ iterNum}vs")
        
        fuzzGuidance.displayStats(true)
        targets.foreach(_.finish(verbose = false))
        logFile.println(s"coverPointsNum: $coverPointsNum") //debug
        logFile.close()
    }
}

//Multi Process
/*
                val multiProcess = new Array[Process](threadNum)
                for (idx <- 0 until threadNum) {
                    val multiProcess[i] = Process("scala", "-e", "
                        val threadId = Thread.currentThread.getId
                        val processName = ManagementFactory.getRuntimeMXBean.getName
                        val processId = processName.split("@")(0).toLong
                        // println(s\"Thread ID: $threadId\")
                        // println(s\"Process ID: $processId\")
                        // Generate input and Save the input
                  		val in_stream = fuzzGuidance.createParameterStream(input)
                  		// Run simulation
                        val t3 = System.nanoTime()
                  		val (coverage0, isValid, cycleNum) = target.run(in_stream, feedbackCap)
                  		in_stream.close()
                        val t4 = System.nanoTime()
                        val runCov = new Coverage(coverage0.toArray)
                  		input.coverage = runCov
                        input.isValid = isValid
                        cycleNums(idx) = cycleNum
                        simTimes(idx)  = (t4-t3) / 1000
                    ").run()
                }
                multiProcess.foreach(_.exitValue())
*/

