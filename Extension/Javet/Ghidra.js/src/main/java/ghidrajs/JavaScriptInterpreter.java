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
import java.util.stream.Collectors;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import com.caoccao.javet.exceptions.JavetException;
import com.caoccao.javet.interop.V8Host;
import com.caoccao.javet.interop.V8Runtime;
import com.caoccao.javet.interop.NodeRuntime;
import com.caoccao.javet.interop.engine.IJavetEngine;
import com.caoccao.javet.interop.engine.IJavetEnginePool;
import com.caoccao.javet.interop.engine.JavetEnginePool;
import com.caoccao.javet.interop.V8ScriptOrigin;
import com.caoccao.javet.values.V8Value;
import com.caoccao.javet.values.reference.V8ValueProxy;
import com.caoccao.javet.values.reference.V8ValueObject;
import com.caoccao.javet.interop.converters.JavetProxyConverter;
import com.caoccao.javet.values.reference.IV8ValueArray;
import com.caoccao.javet.utils.ThreadSafeMap;
import com.caoccao.javet.interop.binding.BindingContext;
import com.caoccao.javet.enums.JSRuntimeType;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.Arrays;


public class JavaScriptInterpreter implements Disposable {
    public class JavaTypeProvider {
      public Class<?> getClass(String className) throws ClassNotFoundException {
          return Class.forName(className);
      }
    }

    private boolean useNode = true;
    private Map<String, Object> setVariables = new HashMap<String, Object>();
    private V8Runtime cx = null;
    private V8ValueObject scope;
    private IJavetEnginePool<V8Runtime> javetEnginePoolV8;
    private IJavetEnginePool<NodeRuntime> javetEnginePoolNode;

    private Pattern completionPattern = Pattern.compile("[\\w.]+$");
    private boolean disposed = false;
    private JavaScriptPlugin parentPlugin;
    private InterpreterConsole savedConsole;
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

    private V8Runtime getRuntime() throws JavetException {
        if (useNode) {
          if (javetEnginePoolNode == null) {
            javetEnginePoolNode = new JavetEnginePool<>();
            javetEnginePoolNode.getConfig().setJSRuntimeType(JSRuntimeType.Node);
          }
          IJavetEngine<NodeRuntime> javetEngine = javetEnginePoolNode.getEngine();
          NodeRuntime nodeRuntime = javetEngine.getV8Runtime();
          JavetProxyConverter javetProxyConverter = new JavetProxyConverter();
          nodeRuntime.setConverter(javetProxyConverter);
          return nodeRuntime;
        }
        else {
          if (javetEnginePoolV8 == null) {
            javetEnginePoolV8 = new JavetEnginePool<>();
          }
          IJavetEngine<V8Runtime> javetEngine = javetEnginePoolV8.getEngine();
          V8Runtime v8Runtime = javetEngine.getV8Runtime();
          JavetProxyConverter javetProxyConverter = new JavetProxyConverter();
          v8Runtime.setConverter(javetProxyConverter);
          return v8Runtime;
        }
    }

    public void initInteractiveInterpreter() throws JavetException {
        cx = getRuntime();
        scope = cx.getGlobalObject();

        ConsoleLogger consoleLogger = new ConsoleLogger(outWriter, errWriter);
        scope.set("console", consoleLogger);
        JavaTypeProvider javaTypeProvider = new JavaTypeProvider();
        V8Value javaTypeProviderProxy = cx.toV8Value(javaTypeProvider);
        scope.set("JavaHelper", javaTypeProviderProxy);


        setVariables.forEach((name, value) -> {
          try {
            scope.set(name, value);
          } catch(JavetException e) {
            errWriter.println("Erorr initializing Javet: " + e.getMessage());
          }
        });
    }

    public void initInteractiveInterpreterWithProgress(PrintWriter output, PrintWriter errOut) throws JavetException {
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
        savedConsole = console;
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

    private boolean isIncompleteSource(JavetException e) {
      return e.getMessage().contains("Unexpected end of input");
    }

    private Runnable replLoop = () -> {
        try {
            initInteractiveInterpreterWithProgress(outWriter, errWriter);
        } catch(JavetException e) {
            return;
        }
        int lineno = 1;

        InputReader inputReader = new InputReader(input);
        inputReader.startReading();
        String source = "";
        V8ScriptOrigin origin = new V8ScriptOrigin("<stdin>");
        savedConsole.setPrompt("> ");
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
                if (source.trim().isEmpty()) continue;
                try (V8Value v8Value = cx.getExecutor(source).execute()) {
                    if (v8Value != null) {
                          outWriter.println(v8Value.toString());
                    }
                    source = "";
                    savedConsole.setPrompt("> ");
                } catch (JavetException e) {
                    if (isIncompleteSource(e)) {
                        savedConsole.setPrompt("... ");
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

    public List<CodeCompletion> getCompletions(String inputCmd, int caretPos) {
        Callable<List<CodeCompletion>> callable = () -> {
            List<CodeCompletion> completions = new ArrayList<>();
            String cmd = inputCmd.substring(0, caretPos);
            Matcher matcher = completionPattern.matcher(cmd);
            if (matcher.find()) {
                String matchedInput = matcher.group();
                String[] members = matchedInput.split("\\.");
                boolean endsWithDot = matchedInput.charAt(matchedInput.length() - 1) == '.';
                String lastKey = endsWithDot ? "" : members[members.length - 1];
                V8ValueObject current = scope;
                try {
                    /* Maybe this is the correct way, but that way it's not possible to capture variables, so we use eval...
                     * for (int i = 0; i < members.length - (endsWithDot ? 0 : 1); ++i) {
                     *     V8ValueObject next = current.get(members[i]);
                     *     if (current != scope) {
                     *       current.close();
                     *     }
                     *     current = next;
                     * }
                    */

                    int rightOffset = endsWithDot ? 0 : 1;
                    if (members.length > rightOffset) {
                        String evalString = String.join(".", Arrays.copyOfRange(members, 0, members.length - rightOffset)); 
                        current = cx.getExecutor(evalString).execute();
                    }
                    
                    Set<String> candidates;
                    if (current instanceof V8ValueProxy) {
                        Object currentObject = cx.toObject(current);
                        candidates = new HashSet<>();
                        Class<?> clazz = currentObject.getClass();
                        Field[] fields = clazz.getFields();
                        for (Field field : fields) {
                            if (Modifier.isPublic(field.getModifiers())) {
                                String name = field.getName();
                                if (name.startsWith(lastKey)) {
                                    candidates.add(name);
                                }
                            }
                        }
                        Method[] methods = clazz.getMethods();
                        for (Method method : methods) {
                            if (Modifier.isPublic(method.getModifiers())) {
                                String name = method.getName();
                                if (name.startsWith(lastKey)) {
                                    candidates.add(name + "(");
                                }
                            }
                        }
                    }
                    else {
                      candidates = current
                        .getOwnPropertyNameStrings()
                        .stream()
                        .filter(e -> {
                          return e.startsWith(lastKey);
                        })
                        .collect(Collectors.toSet());
                    }

                    for (String candidate : candidates) {
                        completions.add(new CodeCompletion(candidate, candidate.substring(lastKey.length()), null));
                    }
                } catch(Exception e) {
                  //For debug
                  //errWriter.println("Completion exception: " + e.getMessage());
                } finally {
                    if (current != scope) {
                      current.close();
                    }
                }
            }

            return completions;
        };

        List<CodeCompletion> emptyList = new ArrayList<CodeCompletion>();

        FutureTask<List<CodeCompletion>> futureTask = new FutureTask<>(callable);

        try {
            taskQueue.put(futureTask);
            List<CodeCompletion> completions = futureTask.get(1, TimeUnit.SECONDS);
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
            try {
              cx.close();
            } catch(JavetException e) {

            }
            cx = null;
        }
        disposed = true;
    }

    public JavaScriptPlugin getParentPlugin() {
        return parentPlugin;
    }

    public String getVersion() throws JavetException {
        String version = getRuntime().getVersion().toString();
        return "JavaScript (Javet " + version + ")";
    }

    public void runScript(GhidraScript script, String[] scriptArguments, GhidraState scriptState) throws IllegalArgumentException, FileNotFoundException, IOException {
        try {
            initInteractiveInterpreter();
        } catch(JavetException e) {
            return;
        }
        
        String scriptCode = new String(Files.readAllBytes(Paths.get(script.getSourceFile().getAbsolutePath())), StandardCharsets.UTF_8);
        
        loadState(scriptState);

        try {
          V8Value savedAPI = scope.get(getCurrentAPIName());
          scope.set("script", script);
          scope.set(getCurrentAPIName(), script);
          scope.set("ARGV", scriptArguments);
          
          cx.getExecutor(scriptCode).executeVoid();

          scope.delete("script");
          scope.set(getCurrentAPIName(), savedAPI);
          updateState(scriptState);
        } catch(JavetException e) {
          errWriter.println(e.getMessage());
        }
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
            try {
                scope.set(name, value);
            } catch(JavetException e) {

            }
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
