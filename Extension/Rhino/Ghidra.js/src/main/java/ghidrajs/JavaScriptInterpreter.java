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

import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.mozilla.javascript.ImplementationVersion;
import org.mozilla.javascript.EvaluatorException;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.JavaScriptException;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.WrappedException;
import org.mozilla.javascript.EcmaError;
import org.mozilla.javascript.NativeJavaClass;
import org.mozilla.javascript.ImporterTopLevel;


import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;




public class JavaScriptInterpreter implements Disposable {
    private Map<String, Object> setVariables = new HashMap<String, Object>();
    private Context cx;
    private Scriptable scope;
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
      cx = Context.enter();
      cx.setLanguageVersion(Context.VERSION_ES6);
      //scope = cx.initStandardObjects();
      ScriptableObject importer = new ImporterTopLevel(cx);
      scope = cx.initStandardObjects(importer);

      ConsoleLogger consoleLogger = new ConsoleLogger(outWriter, errWriter);
      ScriptableObject.putProperty(scope, "console", Context.javaToJS(consoleLogger, scope));

      setVariables.forEach((name, value) -> {
        ScriptableObject.putProperty(scope, name, value);
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
        BufferedReader in = new BufferedReader(new InputStreamReader(input));
        String sourceName = "<stdin>";
        int lineno = 1;
        //TODO setup autoimport settings
        /*AtomicInteger packages = new AtomicInteger(0);

        try {
            JavaScriptPlugin.forEachAutoImport((packageName) -> {
              try {
                if (isClass(packageName)) {
                  cx.evaluateString(scope, "importClass(" + packageName + ")", sourceName, 0, null);
                }
                else {
                  cx.evaluateString(scope, "importPackage(" + packageName + ")", sourceName, 0, null);
                }
                packages.incrementAndGet();
              }
              catch (EcmaError err) {
                  errWriter.println("Error preloading class/package " + packageName);
              }
            });
        } catch(JDOMException err) {
            errWriter.println("Error preloading classes");
        } catch(IOException err) {
            errWriter.println("Error preloading classes");
        }*

        outWriter.println("[*] Imported " + packages + " packages");*/

        InputReader inputReader = new InputReader(input);
        inputReader.startReading();
        do {
            Runnable task;
            while ((task = taskQueue.poll()) != null) {
                task.run();
            }
            int startline = lineno;
            try {
                String source = "";
                String newline;
                while ((newline = inputReader.pollInput()) != null) {
                    source = source + newline + "\n";
                    lineno++;
                    if (cx.stringIsCompilableUnit(source)) break;
                }
                if (cx == null) {
                    Thread.currentThread().interrupt();
                    return;
                }
                Object result = cx.evaluateString(scope, source, sourceName, startline, null);
                if (result != Context.getUndefinedValue()) {
                    outWriter.println(Context.toString(result));
                }
            } catch (WrappedException we) {
                errWriter.println(we.getWrappedException().toString());
                we.printStackTrace();
            } catch (EvaluatorException ee) {
                errWriter.println("js: " + ee.getMessage());
            } catch (JavaScriptException jse) {
                errWriter.println("js: " + jse.getMessage());
            } catch (EcmaError err) {
                errWriter.println(err.toString());
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
            List<CodeCompletion> candidates = new ArrayList<>();
            //TODO make this work
            return candidates;
            /*String[] names = cmd.split("\\.", -1);
            Scriptable obj = scope;
            for (int i = 0; i < names.length - 1; i++) {
                    Object val = obj.get(names[i], scope);
                    if (val instanceof Scriptable) obj = (Scriptable) val;
                    else {
                            return candidates;
                    }
            }
            Object[] ids =
                            (obj instanceof ScriptableObject)
                                            ? ((ScriptableObject) obj).getAllIds()
                                            : obj.getIds();
            String lastPart = names[names.length - 1];
            for (int i = 0; i < ids.length; i++) {
                outWriter.println(ids[i]);
                if (!(ids[i] instanceof String)) continue;
                String id = (String) ids[i];
                if (id.startsWith(lastPart)) {
                        if (obj.get(id, obj) instanceof Function) id += "(";
                        candidates.add(new CodeCompletion("", id, null));
                }
            }
            return candidates;*/
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
        return org.mozilla.javascript.ImplementationVersion.get();
    }

    public void runScript(GhidraScript script, String[] scriptArguments, GhidraState scriptState) throws IllegalArgumentException, FileNotFoundException, IOException {
        initInteractiveInterpreter();    // Initialize Rhino context and scope
        
        String scriptCode = new String(Files.readAllBytes(Paths.get(script.getSourceFile().getAbsolutePath())), StandardCharsets.UTF_8);
        
        loadState(scriptState);

        Object savedAPI = scope.get(getCurrentAPIName(), scope);
        scope.put("script", scope, script);
        scope.put(getCurrentAPIName(), scope, script);    // Assuming getCurrentAPIName() returns a valid name
        scope.put("ARGV", scope, scriptArguments);
        
        cx.evaluateString(scope, scriptCode, script.getScriptName(), 1, null);

        ScriptableObject.deleteProperty(scope, "script");
        ScriptableObject.putProperty(scope, getCurrentAPIName(), savedAPI);    // Assuming savedAPI is defined and applicable
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
            ScriptableObject.putProperty(scope, name, value);
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
