package ghidrajs;

import org.jdom.JDOMException;

import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.program.util.ProgramSelection;

import ghidra.util.Disposable;
import ghidra.util.Msg;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;

import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Source;
import org.graalvm.polyglot.Value;
import org.graalvm.polyglot.PolyglotException;
import org.graalvm.polyglot.Context.Builder;
import org.graalvm.home.Version;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;


public class JavaScriptInterpreter implements Disposable {
    private String initScript = 
        "function requireJava(className) {\n" +
        "    return Java.type(className);\n" +
        "}\n";

    private Map<String, Object> setVariables = new HashMap<String, Object>();
    private Context cx;
    private Value scope;

    private boolean disposed = false;
    private JavaScriptPlugin parentPlugin;
    private PrintWriter outWriter = null;
    private PrintWriter errWriter = null;
    private InputStream input = null;
    private Thread jsThread;
    private Thread readerThread;
    private BlockingQueue<Runnable> taskQueue = new LinkedBlockingQueue<>();
    private BlockingQueue<Runnable> lineQueue = new LinkedBlockingQueue<>();

    public String getCurrentAddressName() {
        return "currentAddress";
    }

    public String getCurrentAPIName() {
        return "currentAPI";
    }

    public String getCurrentHighlightName() {
        return "currentHighlight";
    }

    public String getCurrentLocationName() {
        return "currentLocation";
    }

    public String getCurrentProgramName() {
        return "currentProgram";
    }

    public String getCurrentSelectionName() {
        return "currentSelection";
    }


    public void initInteractiveInterpreter() {
        cx = Context.newBuilder("js").allowAllAccess(true).allowIO(true).build();
        scope = cx.getBindings("js");

        Source initSrc = Source.newBuilder("js", initScript, "<stdin>").cached(false).buildLiteral();
        cx.eval(initSrc);

        ConsoleLogger consoleLogger = new ConsoleLogger(outWriter, errWriter);
        scope.putMember("console", consoleLogger);

        setVariables.forEach((name, value) -> {
            scope.putMember(name, value);
        });
    }

    public void initInteractiveInterpreterWithProgress(PrintWriter output, PrintWriter errOut) {
        long startTime = System.currentTimeMillis();
        output.append("starting " + getVersion() + "\n");
        output.flush();

        initInteractiveInterpreter();

        long endTime = System.currentTimeMillis();
        double loadTime = (endTime - startTime) / 1000.0;
        output.append(String.format("startup finished (%.3f seconds)\n", loadTime));
        output.flush();
    }

    public void setStreams(InterpreterConsole console) {
        setInput(console.getStdin());
        setOutWriter(console.getOutWriter());
        setErrWriter(console.getErrWriter());
    }

    public void updateAddress(Address address) {
        setVariable(getCurrentAddressName(), address);
    }

    public void updateHighlight(ProgramSelection sel) {
        if (sel != null) {
            setVariable(getCurrentHighlightName(), sel);
        }
    }

    public void updateLocation(ProgramLocation loc) {
        if (loc != null) {
            setVariable(getCurrentLocationName(), loc);
            updateAddress(loc.getAddress());
        }
    }

    public void updateProgram(Program program) {
        if (program != null) {
            setVariable(getCurrentProgramName(), program);
            setVariable(getCurrentAPIName(), new FlatProgramAPI(program));
        }
    }

    public void updateSelection(ProgramSelection sel) {
        setVariable(getCurrentSelectionName(), sel);
    }

    public boolean isClass(String name) {
        try {
            Class.forName(name);
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    private Runnable replLoop = () -> {
        initInteractiveInterpreterWithProgress(outWriter, errWriter);
        int lineno = 1;

        InputReader inputReader = new InputReader(input);
        inputReader.startReading();
        String source = "";
        do {
            Runnable task;
            while ((task = taskQueue.poll()) != null) {
                task.run();
            }
            int startline = lineno;
            if (cx == null) {
                Thread.currentThread().interrupt();
                return;
            }
            String newline;
            while ((newline = inputReader.pollInput()) != null) {
                source = source + newline + "\n";
                lineno++;
                try {
                  Source graalSrc = Source.newBuilder("js", source, "<stdin>").cached(false).buildLiteral();
                  Value result = cx.eval(graalSrc);
                  if (result.as(Object.class) != null) {
                    outWriter.println(result.toString());
                    break;
                  }
                  source = "";
                } catch (PolyglotException e) {
                    if (e.isIncompleteSource()) {
                        continue;
                    } else {
                        errWriter.println("<stdin>:" + lineno + ": " + e.getMessage());
                        source = "";
                        break;
                    }
                }
            }
        } while (true);
    };


    public JavaScriptInterpreter() {
        cx = null;
        parentPlugin = null;
    }

    public JavaScriptInterpreter(InterpreterConsole console, JavaScriptPlugin plugin) {
        setStreams(console);
        parentPlugin = plugin;
        jsThread = new Thread(replLoop);
    }

    public List<CodeCompletion> getCompletions(String cmd) {
        Callable<List<CodeCompletion>> callable = () -> {
            //TODO
            List<CodeCompletion> completions = new ArrayList<>();
            return completions;
        };

        List<CodeCompletion> emptyList = new ArrayList<CodeCompletion>();

        FutureTask<List<CodeCompletion>> futureTask = new FutureTask<>(callable);

        try {
            taskQueue.put(futureTask);
            List<CodeCompletion> completions = futureTask.get(2, TimeUnit.SECONDS);
            return completions;
        } catch (InterruptedException e) {
            errWriter.println(e.toString());
        } catch (ExecutionException e) {
            errWriter.println(e.toString());
        } catch (TimeoutException e) {
            errWriter.println("Task timed out");
        }

        return emptyList;
    }

    public void dispose() {
        if (jsThread != null && jsThread.isAlive()) {
            jsThread.interrupt();
        }
        if (cx != null) {
            cx = null;
        }
        disposed = true;
    }

    public JavaScriptPlugin getParentPlugin() {
        return parentPlugin;
    }

    public String getVersion() {
        String version = Version.getCurrent().toString();
        return "JavaScript (org.graalvm.js " + version + ")";
    }

    public void runScript(GhidraScript script, String[] scriptArguments, GhidraState scriptState) throws IllegalArgumentException, FileNotFoundException, IOException {
        initInteractiveInterpreter();
        
        String scriptCode = new String(Files.readAllBytes(Paths.get(script.getSourceFile().getAbsolutePath())), StandardCharsets.UTF_8);
        
        loadState(scriptState);

        Value savedAPI = scope.getMember(getCurrentAPIName());
        scope.putMember("script", script);
        scope.putMember(getCurrentAPIName(), script);
        scope.putMember("ARGV", scriptArguments);
        
        cx.eval(Source.newBuilder("js", scriptCode, script.getScriptName()).build());

        scope.removeMember("script");
        scope.putMember(getCurrentAPIName(), savedAPI);
        updateState(scriptState);
    }

    public void setErrWriter(PrintWriter errOut) {
        errWriter = errOut;
    }

    public void setInput(InputStream input) {
        this.input = input;
    }

    public void setOutWriter(PrintWriter output) {
        outWriter = output;
    }

    public void setVariable(String name, Object value) {
        setVariables.put(name, value);
        if (cx != null) {
            scope.putMember(name, value);
        }
    }

    public void startInteractiveSession() {
        jsThread.start();
    }

    public void loadState(GhidraState state) {
        updateHighlight(state.getCurrentHighlight());
        updateLocation(state.getCurrentLocation());
        updateSelection(state.getCurrentSelection());
        updateProgram(state.getCurrentProgram());

        updateAddress(state.getCurrentAddress());
    }

    public void updateState(GhidraState scriptState) {
        scriptState.setCurrentProgram((Program) setVariables.get(getCurrentProgramName()));
        scriptState.setCurrentLocation((ProgramLocation) setVariables.get(getCurrentLocationName()));
        scriptState.setCurrentAddress((Address) setVariables.get(getCurrentAddressName()));
        scriptState.setCurrentHighlight((ProgramSelection) setVariables.get(getCurrentHighlightName()));
        scriptState.setCurrentSelection((ProgramSelection) setVariables.get(getCurrentSelectionName()));
    }
}
