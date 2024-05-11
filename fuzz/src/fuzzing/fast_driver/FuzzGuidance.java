package fuzzing.fast;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.collections.api.iterator.IntIterator;
import org.eclipse.collections.api.list.primitive.IntList;
import org.eclipse.collections.impl.set.mutable.primitive.IntHashSet;

import static java.lang.Math.ceil;
import static java.lang.Math.log;

import fuzzing.fast.util.GuidanceException;
import fuzzing.fast.util.IOUtils;
import fuzzing.fast.util.Coverage;


public class FuzzGuidance {
    
    /** A pseudo-random number generator for generating fresh values. */
    protected Random random;

    /** The name of the test for display purposes. */
    protected final String testName;

    // ------------ ALGORITHM BOOKKEEPING ------------

    /** The max amount of time to run for, in milli-seconds */
    protected final long maxDurationMillis;

    /** The max number of trials to run */
    protected final long maxTrials;

    /** The number of trials completed. */
    protected long numTrials = 0;

    /** The number of valid inputs. */
    protected long numValid = 0;

    /** The directory where fuzzing results are produced. */
    protected final File outputDirectory;

     /** The directory where interesting inputs are saved. */
    protected File savedCorpusDirectory;

    /** The directory where all generated inputs are logged in sub-directories (if enabled). */
    protected File allInputsDirectory;

    /** Set of saved inputs to fuzz. */
    protected ArrayList<Input> savedInputs = new ArrayList<>();
    //sort according to fitness

    /** Queue of seeds to fuzz. */
    protected Deque<Input> seedInputs = new ArrayDeque<>();

    /** Current input that's running -- valid after getInput() and before handleResult(). */
    protected Input<?> currentInput;

     /** Index of currentInput in the savedInputs -- valid after seeds are processed (OK if this is inaccurate). */
    protected int currentParentInputIdx = 0;

    /** Number of mutated inputs generated from currentInput. */
    protected int numChildrenGeneratedForCurrentParentInput = 0;


    /** Number of cycles completed (i.e. how many times we've reset currentParentInputIdx to 0. */
    protected int cyclesCompleted = 0;

    /** Number of favored inputs in the last cycle. */
    protected int numFavoredLastCycle = 0;

    /** Validity fuzzing -- if true then save valid inputs that increase valid coverage */
    protected boolean validityFuzzing = true;

    /** Number of saved inputs.
     *
     * This is usually the same as savedInputs.size(),
     * but we do not really save inputs in TOTALLY_RANDOM mode.
     */
    protected int numSavedInputs = 0;


    /** Cumulative coverage statistics. */
    protected Coverage totalCoverage = new Coverage();

    /** Cumulative coverage for valid inputs. */
    protected Coverage validCoverage = new Coverage();



    /** The maximum number of keys covered by any single input found so far. */
    protected int maxCoverage = 0;

    /** A mapping of coverage keys to inputs that are responsible for them. */
    protected Map<Object, Input> responsibleInputs = new HashMap<>(totalCoverage.size());

    // ---------- LOGGING / STATS OUTPUT ------------

    /** Whether to print log statements to stderr (debug option; manually edit). */
    protected final boolean verbose = true;

    /** A system console, which is non-null only if STDOUT is a console. */
    protected final Console console = System.console();

    /** Time since this guidance instance was created. */
    protected final Date startTime = new Date();

    /** Time at last stats refresh. */
    protected Date lastRefreshTime = startTime;

    /** Total execs at last stats refresh. */
    protected long lastNumTrials = 0;

    /** Minimum amount of time (in millis) between two stats refreshes. */
    protected final long STATS_REFRESH_TIME_PERIOD = 300;

    /** The file where log data is written. */
    protected File logFile;

    /** The file where saved plot data is written. */
    protected File statsFile;

    /** The currently executing input (for debugging purposes). */
    protected File currentInputFile;

    /** The file contianing the coverage information */
    protected File coverageFile;

    /** Use libFuzzer like output instead of AFL like stats screen (https://llvm.org/docs/LibFuzzer.html#output) **/
    protected final boolean LIBFUZZER_COMPAT_OUTPUT = true;

    /** Whether to hide fuzzing statistics **/
    protected final boolean QUIET_MODE = false;

    /** Whether to store all generated inputs to disk (can get slowww!) */
    protected final boolean LOG_ALL_INPUTS = false;



    // ------------- THREAD HANDLING ------------

    /** Whether the application has more than one thread running coverage-instrumented code */
    protected boolean multiThreaded = true;


    // ------------- FUZZING HEURISTICS ------------
    /** Whether to save only valid inputs **/
    protected final boolean SAVE_ONLY_VALID = false;

    /** Max input size to generate. */
    protected final int MAX_INPUT_SIZE = 10240;

    /** Whether to generate EOFs when we run out of bytes in the input, instead of randomly generating new bytes. **/
    protected final boolean GENERATE_EOF_WHEN_OUT = true;

    /** Baseline number of mutated children to produce from a given parent input. */
    protected final int NUM_CHILDREN_BASELINE = 100;

    /** The possibility to splice two children to produce from a given parent input. */
    protected final double SPLICE_POSSIBILITY = 0.1;

    /** Multiplication factor for number of children to produce for favored inputs. */
    protected final int NUM_CHILDREN_MULTIPLIER_FAVORED = 40;

    /** Mean number of mutations to perform in each round. */
    protected final double MEAN_MUTATION_COUNT = 4;

    /** Mean number of contiguous bytes to mutate in each mutation. */
    protected final double MEAN_MUTATION_SIZE = 1.0; // Bytes

    protected final boolean CONSTANT_MUTATION_SIZE = true;


    /** Whether to save inputs that only add new coverage bits (but no new responsibilities). */
    protected final boolean DISABLE_SAVE_NEW_COUNTS = false;

    /** Whether to steal responsibility from old inputs (this increases computation cost). */
    // protected final boolean STEAL_RESPONSIBILITY = Boolean.getBoolean("jqf.ei.STEAL_RESPONSIBILITY");



    /**
     * Creates a new Zest guidance instance with optional duration,
     * optional trial limit, and possibly deterministic PRNG.
     *
     * @param testName the name of test to display on the status screen
     * @param duration the amount of time to run fuzzing for, where
     *                 {@code null} indicates unlimited time.
     * @param trials   the number of trials for which to run fuzzing, where
     *                 {@code null} indicates unlimited trials.
     * @param outputDirectory the directory where fuzzing results will be written
     * @param sourceOfRandomness      a pseudo-random number generator
     * @throws IOException if the output directory could not be prepared
     */
    public FuzzGuidance(String testName, Duration duration, Long trials, File outputDirectory, Random sourceOfRandomness) throws IOException {
        this.random = sourceOfRandomness;
        this.testName = testName;
        this.maxDurationMillis = duration != null ? duration.toMillis() : Long.MAX_VALUE;
        this.maxTrials = trials != null ? trials : Long.MAX_VALUE;
        this.outputDirectory = outputDirectory;
        prepareOutputDirectory();
    }

    public FuzzGuidance(String testName, Duration duration, Long trials, File outputDirectory, File seedInputDir) throws IOException {
        this(testName, duration, trials, outputDirectory, new Random());
        File[] seedInputFiles = IOUtils.resolveInputFileOrDirectory(seedInputDir);
        if (seedInputFiles != null) {
            for (File seedInputFile : IOUtils.resolveInputFileOrDirectory(seedInputDir)) {
                seedInputs.add(new SeedInput(seedInputFile));
            }
        }
    }

    private void prepareOutputDirectory() throws IOException {
        // Create the output directory if it does not exist
        IOUtils.createDirectory(outputDirectory);

        // Name files and directories after AFL
        this.savedCorpusDirectory = IOUtils.createDirectory(outputDirectory, "corpus");

        if (LOG_ALL_INPUTS) {
            this.allInputsDirectory = IOUtils.createDirectory(outputDirectory, "all");
            IOUtils.createDirectory(allInputsDirectory, "success");
        }

        this.statsFile = new File(outputDirectory, "plot_data");
        this.logFile = new File(outputDirectory, "fuzz.log");
        this.currentInputFile = new File(outputDirectory, ".cur_input");
        this.coverageFile = new File(outputDirectory, "coverage_hash");

        // Delete everything that we may have created in a previous run.
        // Trying to stay away from recursive delete of parent output directory in case there was a
        // typo and that was not a directory we wanted to nuke.
        // We also do not check if the deletes are actually successful.
        statsFile.delete();
        logFile.delete();
        coverageFile.delete();
        for (File file : savedCorpusDirectory.listFiles()) {
            file.delete();
        }
    }
    
    /* Writes a line of text to a given log file. */
    protected void appendLineToFile(File file, String line) throws GuidanceException {
        try (PrintWriter out = new PrintWriter(new FileWriter(file, true))) {
            out.println(line);
        } catch (IOException e) {
            throw new GuidanceException(e);
        }

    }

    /* Writes a line of text to the log file. */
    protected void infoLog(String str, Object... args) {
        if (verbose) {
            String line = String.format(str, args);
            if (logFile != null) {
                appendLineToFile(logFile, line);

            } else {
                System.err.println(line);
            }
        }
    }

    protected String millisToDuration(long millis) {
        long seconds = TimeUnit.MILLISECONDS.toSeconds(millis % TimeUnit.MINUTES.toMillis(1));
        long minutes = TimeUnit.MILLISECONDS.toMinutes(millis % TimeUnit.HOURS.toMillis(1));
        long hours = TimeUnit.MILLISECONDS.toHours(millis);
        String result = "";
        if (hours > 0) {
            result = hours + "h ";
        }
        if (hours > 0 || minutes > 0) {
            result += minutes + "m ";
        }
        result += seconds + "s";
        return result;
    }

    public void displayStats(boolean force) {
        Date now = new Date();
        long intervalMilliseconds = now.getTime() - lastRefreshTime.getTime();
        intervalMilliseconds = Math.max(1, intervalMilliseconds);
        if (intervalMilliseconds < STATS_REFRESH_TIME_PERIOD && !force) {
            return;
        }
        long interlvalTrials = numTrials - lastNumTrials;
        long intervalExecsPerSec = interlvalTrials * 1000L;
        double intervalExecsPerSecDouble = interlvalTrials * 1000.0;
        if(intervalMilliseconds != 0) {
            intervalExecsPerSec = interlvalTrials * 1000L / intervalMilliseconds;
            intervalExecsPerSecDouble = interlvalTrials * 1000.0 / intervalMilliseconds;
        }
        lastRefreshTime = now;
        lastNumTrials = numTrials;
        long elapsedMilliseconds = now.getTime() - startTime.getTime();
        elapsedMilliseconds = Math.max(1, elapsedMilliseconds);
        long execsPerSec = numTrials * 1000L / elapsedMilliseconds;

        String currentParentInputDesc;
        if (seedInputs.size() > 0 || savedInputs.isEmpty()) {
            currentParentInputDesc = "<seed>";
        } else {
            Input currentParentInput = savedInputs.get(currentParentInputIdx);
            currentParentInputDesc = currentParentInputIdx + " ";
            currentParentInputDesc += currentParentInput.isFavored() ? "(favored)" : "(not favored)";
            currentParentInputDesc += " {" + numChildrenGeneratedForCurrentParentInput +
                    "/" + getTargetChildrenForParent(currentParentInput) + " mutations}";
        }

        int nonZeroCount = totalCoverage.getNonZeroCount();
        double nonZeroFraction = nonZeroCount * 100.0 / totalCoverage.size();
        int nonZeroValidCount = validCoverage.getNonZeroCount();
        double nonZeroValidFraction = nonZeroValidCount * 100.0 / validCoverage.size();

        
        if (LIBFUZZER_COMPAT_OUTPUT) {
            System.out.printf("#%,d\tNEW\tcov: %,d exec/s: %,d L: %,d\n", numTrials, nonZeroCount, intervalExecsPerSec, currentInput.size());
        } else if (!QUIET_MODE) {
            System.out.printf("\033[2J");
            System.out.printf("\033[H");
            System.out.printf(this.getTitle() + "\n");
            if (this.testName != null) {
                System.out.printf("Test name:            %s\n", this.testName);
            }

            System.out.printf("Results directory:    %s\n", this.outputDirectory.getAbsolutePath());
            System.out.printf("Elapsed time:         %s (%s)\n", millisToDuration(elapsedMilliseconds),
                    maxDurationMillis == Long.MAX_VALUE ? "no time limit" : ("max " + millisToDuration(maxDurationMillis)));
            System.out.printf("Number of executions: %,d (%s)\n", numTrials,
                            maxTrials == Long.MAX_VALUE ? "no trial limit" : ("max " + maxTrials));
            System.out.printf("Cycles completed:     %d\n", cyclesCompleted);
            System.out.printf("Queue size:           %,d (%,d favored last cycle)\n", savedInputs.size(), numFavoredLastCycle);
            System.out.printf("Current parent input: %s\n", currentParentInputDesc);
            System.out.printf("Execution speed:      %,d/sec now | %,d/sec overall\n", intervalExecsPerSec, execsPerSec);
            System.out.printf("Total coverage:       %,d branches (%.2f%% of map)\n", nonZeroCount, nonZeroFraction);
        }
        

        String plotData = String.format("time: %d, trials: %d, valid: %d, fuzz_cycle: %d, saved_inputs: %d, total_cov: %.2f%%, valid_cov: %.2f%%, fps: %.2f",
                TimeUnit.MILLISECONDS.toSeconds(now.getTime()), numTrials, numValid, cyclesCompleted, numSavedInputs, nonZeroFraction, nonZeroValidFraction, intervalExecsPerSecDouble);
        appendLineToFile(statsFile, plotData);
    }

    /** Updates the data in the coverage file */
    protected void updateCoverageFile() {
        try {
            PrintWriter pw = new PrintWriter(coverageFile);
            pw.println(totalCoverage.toString());
            pw.println("Hash code: " + totalCoverage.hashCode());
            pw.close();
        } catch (FileNotFoundException ignore) {
            throw new GuidanceException(ignore);
        }
    }

    protected String getTitle() {
        return "Fast hardware fuzzing \n" + 
        "--------------------------------------------\n";
    }

    protected int getTargetChildrenForParent(Input parentInput) {
        // Baseline is a constant
        int target = NUM_CHILDREN_BASELINE;

        // We like inputs that cover many things, so scale with fraction of max
        if (maxCoverage > 0) {
            if(parentInput instanceof SeedInput) {
                target = NUM_CHILDREN_BASELINE;
            } else {
                target = (NUM_CHILDREN_BASELINE * parentInput.nonZeroCoverage) / maxCoverage;
            }
        }

        // We absolutely love favored inputs, so fuzz them more
        if (parentInput.isFavored()) {
            target = target * NUM_CHILDREN_MULTIPLIER_FAVORED;
        }

        
        return target;
    }

    /** Handles the end of fuzzing cycle (i.e., having gone through the entire queue) */
    protected void completeCycle() {
        // Increment cycle count
        cyclesCompleted++;
        infoLog("\n# Cycle " + cyclesCompleted + " completed.");

        // Go over all inputs and do a sanity check (plus log)
        infoLog("Here is a list of favored inputs:");
        int sumResponsibilities = 0;
        numFavoredLastCycle = 0;
        for (Input input : savedInputs) {
            if (input.isFavored()) {
                int responsibleFor = input.responsibilities.size();
                infoLog("Input %d is responsible for %d branches", input.id, responsibleFor);
                sumResponsibilities += responsibleFor;
                numFavoredLastCycle++;
            }
        }
        int totalCoverageCount = totalCoverage.getNonZeroCount();
        infoLog("Total %d branches covered", totalCoverageCount);
        if (sumResponsibilities != totalCoverageCount) {
            if (multiThreaded) {
                infoLog("Warning: other threads are adding coverage between test executions");
            } else {
                throw new AssertionError("Responsibilty mismatch");
            }
        }

        // Break log after cycle
        infoLog("\n\n\n");
    }

    /**
     * Spawns a new input from thin air (i.e., actually random)
     *
     * @return a fresh input
     */
    protected Input<?> createFreshInput() {
        return new LinearInput();
    }

    /**
     * Returns an InputStream that delivers parameters to the generators.
     *
     * Note: The variable `currentInput` has been set to point to the input
     * to mutate.
     *
     * @return an InputStream that delivers parameters to the generators
     */
    public InputStream createParameterStream(Input input) {
        // Return an input stream that reads bytes from a linear array
        return new InputStream() {
            // For linear inputs, get with key = bytesRead (which is then incremented)
            Input input_this = input;
            // LinearInput input_this = new LinearInput((LinearInput)input);
            int bytesRead = 0;

            @Override
            public int read() throws IOException {
                assert input_this instanceof LinearInput : "FuzzGuidance should only mutate LinearInput(s)";
                
                // For linear inputs, get with key = bytesRead (which is then incremented)
                LinearInput linearInput = (LinearInput) input_this;
                // Attempt to get a value from the list, or else generate a random value
                int ret = linearInput.getOrGenerateFresh(bytesRead++, random);
                // infoLog("read(%d) = %d", bytesRead, ret);
                return ret;
            }
        };
    }

    public Input[][] getInputs(int dim, int threadNum) {
        return new Input[dim][threadNum];
    }

    public int getMaxCoverage() {
        return maxCoverage;
    }

    public Input getCopyInput(Input input) throws IOException {
        // try {
            if(input instanceof SeedInput)
                return input;
            else
                return new LinearInput((LinearInput)input);
    }

    public Input getInput() throws GuidanceException { //here
    // public Input[] getInput(int inputNum) throws GuidanceException { //here
        // AtomicReference<Input> inputRet = new AtomicReference<>();
        // conditionallySynchronize(multiThreaded, () -> {
            // // Clear coverage stats for this run
        // var inputs = new Input[inputNum];
        // for (int i = 0; i < inputNum; i++) {
            // Choose an input to execute based on state of queues
            if (!seedInputs.isEmpty()) { //get from seedInputs first
                // System.out.println("Get seed input");

                // First, if we have some specific seeds, use those
                currentInput = seedInputs.removeFirst();

                // Hopefully, the seeds will lead to new coverage and be added to saved inputs

            } else if (savedInputs.isEmpty()) {
                // System.out.println("savedInputs empty");
                
                // If no seeds given try to start with something random
                // if (!blind && numTrials > 100_000) {
                //     throw new GuidanceException("Too many trials without coverage; " +
                //             "likely all assumption violations");
                // }

                // Make fresh input using either list or maps
                // infoLog("Spawning new input from thin air");
                currentInput = createFreshInput();
            } else { //use savedInputs
                // System.out.println("mutate from old saved inputs");

                // The number of children to produce is determined by how much of the coverage
                // pool this parent input hits
                Input currentParentInput = savedInputs.get(currentParentInputIdx);
                int targetNumChildren = getTargetChildrenForParent(currentParentInput);
                //每个savedInputs都作为parent，能够产生targetNumChildren个子Input
                if (numChildrenGeneratedForCurrentParentInput >= targetNumChildren) {
                    // Select the next saved input to fuzz
                    currentParentInputIdx = (currentParentInputIdx + 1) % savedInputs.size();

                    // Count cycles
                    if (currentParentInputIdx == 0) {
                        completeCycle();
                    }

                    numChildrenGeneratedForCurrentParentInput = 0;
                }
                Input parent = savedInputs.get(currentParentInputIdx);

                double rd = random.nextDouble(); //generate a random number to decide whether use splice
                // Splice two children to get a new input
                if(rd<SPLICE_POSSIBILITY) {
                    int ri = random.nextInt(savedInputs.size());
                    currentInput = parent.splice(random, savedInputs.get(ri));
                    numChildrenGeneratedForCurrentParentInput++;
                } 
                // Havoc one children to get a new input
                else { //only use Havoc
                    currentInput = parent.havoc(random);
                    numChildrenGeneratedForCurrentParentInput++;
                }

                // // Write it to disk for debugging
                // try {
                //     writeCurrentInputToFile(currentInputFile);
                // } catch (IOException ignore) {
                // }
            }
            // System.out.println("currentInput values.size():");
            // System.out.println(currentInput.size());
            // if(currentInput instanceof SeedInput) {
            //     inputRet.set(new SeedInput((SeedInput)currentInput));
            // }
            // if(currentInput instanceof LinearInput) {
            //     inputRet.set(new LinearInput((LinearInput)currentInput));
            // }
            // inputRet.set(currentInput);

            // inputs[i] = currentInput;
        // }    

        // });
        // System.out.println("values.size():");
        // System.out.println(((LinearInput)inputRet.get()).values.size());
        // return inputRet.get();
        return currentInput;
        // return inputs;
    }

    //here
    // public void updateSeedCorpus(Input input, byte[] cov, Boolean valid) throws GuidanceException {
    // public void updateSeedCorpus(Input[] inputs) throws GuidanceException {
    public void updateSeedCorpus(Input input) throws GuidanceException {
        // conditionallySynchronize(multiThreaded, () -> { 
            // Coverage runCov = new Coverage(cov);
        // for (Input input : inputs) {
            // Increment run count
            this.numTrials++;
            var runCov = input.coverage;
            var valid = input.isValid;
            // store the seed input whatever
            if(!valid && input instanceof SeedInput) {
                input.gc();
                String why = "initial_seed";
                infoLog("Saving new input (at run %d): " +
                                    "input #%d " +
                                    "of size %d; " +
                                    "reason = %s",
                            numTrials,
                            savedInputs.size(),
                            input.size(),
                            why);
                IntHashSet responsibilities = computeResponsibilities(true, runCov);
                GuidanceException.wrap(() -> saveCurrentInput(input, responsibilities, "seed", runCov));
                updateCoverageFile();
                return;
            }

            if (valid) {
                numValid++;
            }

            if (valid || (!valid && !SAVE_ONLY_VALID)) {
                // long t3 = System.nanoTime();
                // Compute a list of keys for which this input can assume responsibility.
                // Newly covered branches are always included.
                IntHashSet responsibilities = computeResponsibilities(true, runCov);
                // Determine if this input should be saved
                List<String> savingCriteriaSatisfied = checkSavingCriteriaSatisfied(valid, runCov);
                boolean toSave = savingCriteriaSatisfied.size() > 0;
                // long t4 = System.nanoTime();
                // System.out.println("Time for compute tosave: " + (t4 - t3) / 1e9d + " seconds");
                if (toSave) {
                    String why = String.join(" ", savingCriteriaSatisfied);
                    // Trim input (remove unused keys)
                    input.gc();
                    // It must still be non-empty
                    assert (input.size() > 0) : String.format("Empty input: %s", input.desc);
                    // libFuzzerCompat stats are only displayed when they hit new coverage
                    if (LIBFUZZER_COMPAT_OUTPUT) {
                        displayStats(false);
                    }
                    infoLog("Saving new input (at run %d): " +
                                    "input #%d " +
                                    "of size %d; " +
                                    "reason = %s",
                            numTrials,
                            savedInputs.size(),
                            input.size(),
                            why);
                    // Save input to queue and to disk
                    final String reason = why;
                    //保存该input
                    GuidanceException.wrap(() -> saveCurrentInput(input, responsibilities, reason, runCov));
                    // Update coverage information
                    updateCoverageFile();
                }
            } else {
                // The failure of hardware simulation can only be caused by behavior mistake
                // This prototype fuzz framework only focus on how to generate test inputs to achieve coverage closure
                // We haven't handle a failure of hardware simulation yet
                // We only consider success condition now
            }

            // displaying stats on every interval is only enabled for AFL-like stats screen
            // if (!LIBFUZZER_COMPAT_OUTPUT) {
            //     displayStats(false);
            // }

            // Save input unconditionally if such a setting is enabled
            if (LOG_ALL_INPUTS) {
                File logDirectory = new File(allInputsDirectory, "success");
                String saveFileName = String.format("id_%09d", numTrials);
                File saveFile = new File(logDirectory, saveFileName);
                GuidanceException.wrap(() -> writeCurrentInputToFile(input, saveFile));
            }
        // }
        // });
    }


    protected IntHashSet computeResponsibilities(boolean valid, Coverage runCov) {
        IntHashSet result = new IntHashSet();

        // This input is responsible for all new coverage
        IntList newCoverage = runCov.computeNewCoverage(totalCoverage);
        if (newCoverage.size() > 0) {
            result.addAll(newCoverage);
        }

        // If valid, this input is responsible for all new valid coverage
        if (valid) {
            IntList newValidCoverage = runCov.computeNewCoverage(validCoverage);
            if (newValidCoverage.size() > 0) {
                result.addAll(newValidCoverage);
            }
        }

        return result;
    }

    // Return a list of saving criteria that have been satisfied for a non-failure input
    protected List<String> checkSavingCriteriaSatisfied(Boolean valid, Coverage runCov) {
        // Coverage before
        int nonZeroBefore = totalCoverage.getNonZeroCount();
        int validNonZeroBefore = validCoverage.getNonZeroCount();

        // Update total coverage
        boolean coverageBitsUpdated = totalCoverage.updateBits(runCov);
        if (valid == true) {
            validCoverage.updateBits(runCov);
        }


        // Coverage after
        int nonZeroAfter = totalCoverage.getNonZeroCount();
        if (nonZeroAfter > maxCoverage) {
            maxCoverage = nonZeroAfter;
        }
        int validNonZeroAfter = validCoverage.getNonZeroCount();

        // Possibly save input
        List<String> reasonsToSave = new ArrayList<>();


        if (!DISABLE_SAVE_NEW_COUNTS && coverageBitsUpdated) {
            reasonsToSave.add("+count");
        }

        // Save if new total coverage found
        if (nonZeroAfter > nonZeroBefore) {
            reasonsToSave.add("+cov");
        }

        // Save if new valid coverage is found
        if (this.validityFuzzing && validNonZeroAfter > validNonZeroBefore) {
            reasonsToSave.add("+valid");
        }

        return reasonsToSave;
    }
    
    protected void writeCurrentInputToFile(Input input, File saveFile) throws IOException {
        try (BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(saveFile))) {
            for (Integer b : (LinearInput) input) {
                assert (b >= 0 && b < 256);
                out.write(b);
            }
        }

    }

    /* Saves an interesting input to the queue. */
    protected void saveCurrentInput(Input input, IntHashSet responsibilities, String why, Coverage runCov) throws IOException {

        // First, save to disk (note: we issue IDs to everyone, but only write to disk  if valid)
        int newInputIdx = numSavedInputs++;
        String saveFileName = String.format("id_%06d", newInputIdx);
        String how = input.desc;
        File saveFile = new File(savedCorpusDirectory, saveFileName);
        writeCurrentInputToFile(input, saveFile);
        infoLog("Saved - %s %s %s", saveFile.getPath(), how, why);

        // Second, save to queue
        savedInputs.add(input);

        // Third, store basic book-keeping data
        input.id = newInputIdx;
        input.saveFile = saveFile;
        // input.coverage = runCov.copy();
        input.nonZeroCoverage = runCov.getNonZeroCount();
        input.offspring = 0;
        savedInputs.get(currentParentInputIdx).offspring += 1;

        // Fourth, assume responsibility for branches
        input.responsibilities = responsibilities;
        if (responsibilities.size() > 0) {
          input.setFavored();
        }
        IntIterator iter = responsibilities.intIterator();
        while(iter.hasNext()){
            int b = iter.next();
            // If there is an old input that is responsible,
            // subsume it
            Input oldResponsible = responsibleInputs.get(b);
            if (oldResponsible != null) {
                oldResponsible.responsibilities.remove(b);
                // infoLog("-- Stealing responsibility for %s from input %d", b, oldResponsible.id);
            } else {
                // infoLog("-- Assuming new responsibility for %s", b);
            }
            // We are now responsible
            responsibleInputs.put(b, input);
        }
    }


    /**
     * Conditionally run a method using synchronization.
     *
     * This is used to handle multi-threaded fuzzing.
     */
    protected void conditionallySynchronize(boolean cond, Runnable task) {
        if (cond) {
            synchronized (this) {
                task.run();
            }
        } else {
            task.run();
        }
    }


    /**
     * A candidate or saved test input that maps objects of type K to bytes.
     */
    public static abstract class Input<K> implements Iterable<Integer>, Cloneable {

        /**
         * The file where this input is saved.
         *
         * <p>This field is null for inputs that are not saved.</p>
         */
        File saveFile = null;

        /**
         * An ID for a saved input.
         *
         * <p>This field is -1 for inputs that are not saved.</p>
         */
        int id;

        /**
         * Whether this input is favored.
         */
        boolean favored;

        /**
         * The description for this input.
         *
         * <p>This field is modified by the construction and mutation
         * operations.</p>
         */
        String desc;

        /**
         * The run coverage for this input, if the input is saved.
         *
         * <p>This field is null for inputs that are not saved.</p>
         */
        Coverage coverage = null;

        boolean isValid = true;

        /**
         * The number of non-zero elements in `coverage`.
         *
         * <p>This field is -1 for inputs that are not saved.</p>
         *
         * <p></p>When this field is non-negative, the information is
         * redundant (can be computed using {@link Coverage#getNonZeroCount()}),
         * but we store it here for performance reasons.</p>
         */
        int nonZeroCoverage = -1;

        /**
         * The number of mutant children spawned from this input that
         * were saved.
         *
         * <p>This field is -1 for inputs that are not saved.</p>
         */
        int offspring = -1;

        /**
         * The set of coverage keys for which this input is
         * responsible.
         *
         * <p>This field is null for inputs that are not saved.</p>
         *
         * <p>Each coverage key appears in the responsibility set
         * of exactly one saved input, and all covered keys appear
         * in at least some responsibility set. Hence, this list
         * needs to be kept in-sync with {@link #responsibleInputs}.</p>
         */
        IntHashSet responsibilities = null;

        /**
         * Create an empty input.
         */
        public Input() {
            desc = "random";
        }

        /**
         * Create a copy of an existing input.
         *
         * @param toClone the input map to clone
         */
        public Input(Input toClone) {
            desc = String.format("src:%06d", toClone.id);
        }

        public abstract int getOrGenerateFresh(K key, Random random);
        public abstract int size();
        public abstract Input havoc(Random random);
        public abstract Input splice(Random random, Input spliceInput);
        public abstract void gc();

        /**
         * Sets this input to be favored for fuzzing.
         */
        public void setFavored() {
            favored = true;
        }


        /**
         * Returns whether this input should be favored for fuzzing.
         *
         * <p>An input is favored if it is responsible for covering
         * at least one branch.</p>
         *
         * @return whether or not this input is favored
         */
        public boolean isFavored() {
            return favored;
        }

        /**
         * Sample from a geometric distribution with given mean.
         *
         * Utility method used in implementing mutation operations.
         *
         * @param random a pseudo-random number generator
         * @param mean the mean of the distribution
         * @return a randomly sampled value
         */
        public static int sampleGeometric(Random random, double mean) {
            double p = 1 / mean;
            double uniform = random.nextDouble();
            return (int) ceil(log(1 - uniform) / log(1 - p));
        }
    }


    public class LinearInput extends Input<Integer> {

        /** A list of byte values (0-255) ordered by their index. */
        // protected ArrayList<Integer> values;
        public ArrayList<Integer> values;

        /** The number of bytes requested so far */
        protected int requested = 0;

        public LinearInput() {
            super();
            this.values = new ArrayList<>();
        }

        public LinearInput(LinearInput other) {
            super(other);
            this.values = new ArrayList<>(other.values);
        }



        @Override
        public int getOrGenerateFresh(Integer key, Random random) {
            // Otherwise, make sure we are requesting just beyond the end-of-list
            // assert (key == values.size());
            // System.out.println("getOr Generate Fresh");
            // System.out.println(key);
            // System.out.println(requested);
            // System.out.println(values.size());
            // System.out.println(MAX_INPUT_SIZE);
            if (key >= values.size() && GENERATE_EOF_WHEN_OUT) {
                return -1;
            }

            if (key != requested) {
                return -1;
                // throw new IllegalStateException(String.format("Bytes from linear input out of order. " +
                //         "Size = %d, Key = %d", values.size(), key));
            }

            // Don't generate over the limit
            if (requested >= MAX_INPUT_SIZE) {
                return -1;
            }

            // If it exists in the list, return it
            if (key < values.size()) {
                requested++;
                // infoLog("Returning old byte at key=%d, total requested=%d", key, requested);
                return values.get(key);
            }

            // Handle end of stream
            if (GENERATE_EOF_WHEN_OUT) {
                return -1;
            } else {
                // Just generate a random input
                int val = random.nextInt(256);
                values.add(val);
                requested++;
                // infoLog("Generating fresh byte at key=%d, total requested=%d", key, requested);
                return val;
            }
        }

        @Override
        public int size() {
            return values.size();
        }

        /**
         * Truncates the input list to remove values that were never actually requested.
         *
         * <p>Although this operation mutates the underlying object, the effect should
         * not be externally visible (at least as long as the test executions are
         * deterministic).</p>
         */
        @Override
        public void gc() {
            // Remove elements beyond "requested"
            values = new ArrayList<>(values.subList(0, requested));
            values.trimToSize();

            // Inputs should not be empty, otherwise mutations don't work
            if (values.isEmpty()) {
                throw new IllegalArgumentException("Input is either empty or nothing was requested from the input generator.");
            }
        }

        @Override
        public Input havoc(Random random) {
            // Clone this input to create initial version of new child
            LinearInput newInput = new LinearInput(this);

            // Stack a bunch of mutations
            int numMutations = sampleGeometric(random, MEAN_MUTATION_COUNT);
            newInput.desc += ",havoc:"+numMutations;

            boolean setToZero = random.nextDouble() < 0.1; // one out of 10 times

            for (int mutation = 1; mutation <= numMutations; mutation++) {

                // Select a random offset and size
                int offset = random.nextInt(newInput.values.size());
                int mutationSize;
                if(CONSTANT_MUTATION_SIZE) {
                    mutationSize = (int) MEAN_MUTATION_SIZE;
                } else {
                    mutationSize = (int) sampleGeometric(random, MEAN_MUTATION_SIZE);
                }
                // int mutationSize = sampleGeometric(random, MEAN_MUTATION_SIZE);

                // desc += String.format(":%d@%d", mutationSize, idx);

                // Mutate a contiguous set of bytes from offset
                for (int i = offset; i < offset + mutationSize; i++) {
                    // Don't go past end of list
                    if (i >= newInput.values.size()) {
                        break;
                    }

                    // Otherwise, apply a random mutation
                    int mutatedValue = setToZero ? 0 : random.nextInt(256);
                    newInput.values.set(i, mutatedValue);
                }
            }

            return newInput;
        }

        @Override
        public Input splice(Random random, Input spliceInput) {

            LinearInput input2 = (LinearInput) spliceInput;

            int offset1 = random.nextInt(this.values.size());
            int offset2 = random.nextInt(input2.values.size());

            LinearInput newInput = new LinearInput();
            
            for (int i = 0; i < offset1; i++) {
                newInput.values.add(this.values.get(i));
            }
            // for (int i = offset2; i < input2.values.size(); i++) {
            //     newInput.values.add(input2.values.get(i));
            // }
            for (int i = offset1; i < input2.values.size(); i++) {
                newInput.values.add(input2.values.get(i));
            }
            
            newInput.desc += ",splice: id_"+this.id+"&id_"+input2.id;

            return newInput;
        } 


        @Override
        public Iterator<Integer> iterator() {
            return values.iterator();
        }
    }


    public class SeedInput extends LinearInput {
        final File seedFile;
        final InputStream in;

        public SeedInput(File seedFile) throws IOException {
            super();
            this.seedFile = seedFile;
            this.in = new BufferedInputStream(new FileInputStream(seedFile));
            this.desc = "seed";
        }

        public SeedInput(SeedInput toClone) throws IOException {
            super(toClone);
            this.seedFile = toClone.seedFile;
            this.in = new BufferedInputStream(new FileInputStream(seedFile));
            this.desc = "seed";
        }

        @Override
        public int getOrGenerateFresh(Integer key, Random random) {
            int value;
            try {
                value = in.read();
            } catch (IOException e) {
                throw new GuidanceException("Error reading from seed file: " + seedFile.getName(), e);

            }

            // assert (key == values.size())
            if (key != values.size() && value != -1) {
                throw new IllegalStateException(String.format("Bytes from seed out of order. " +
                        "Size = %d, Key = %d", values.size(), key));
            }

            if (value >= 0) {
                requested++;
                values.add(value);
            }

            // If value is -1, then it is returned (as EOF) but not added to the list
            return value;
        }

        @Override
        public void gc() {
            super.gc();
            try {
                in.close();
            } catch (IOException e) {
                throw new GuidanceException("Error closing seed file:" + seedFile.getName(), e);
            }
        }

    }

    
}

