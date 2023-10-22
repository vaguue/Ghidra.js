package ghidrajs;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;


public class JavaScriptProgram extends GhidraScript {

    private JavaScriptInterpreter interpreter;

    public JavaScriptProgram() {
        super();
        interpreter = new JavaScriptInterpreter();
    }

    @Override
    public String getCategory() {
        return "JavaScript";
    }

    @Override
    public void run() {
        final PrintWriter stderr = getStdErr();
        final PrintWriter stdout = getStdOut();

        interpreter.setErrWriter(stderr);
        interpreter.setOutWriter(stdout);

        try {
            interpreter.runScript(this, getScriptArgs(), state);
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        stderr.flush();
        stdout.flush();
    }

    @Override
    public void runScript(String scriptName, String[] scriptArguments, GhidraState scriptState) throws Exception {
        ResourceFile scriptSource = GhidraScriptUtil.findScriptByName(scriptName);
        if (scriptSource == null) {
            boolean shouldContinue = true;

            if (!isRunningHeadless()) {
                // spaces are left between the newlines on purpose
                String question = getScriptName() + " is attempting to run another script " + "[" + scriptName + "]"
                        + " that does not exist or can not be found.\n \n"
                        + "You can silently ignore this error, which could lead to bad results (choose Yes)\n"
                        + "or allow the calling script to receive the error (choose No).\n \n"
                        + "Do you wish to suppress this error?";
                shouldContinue = askYesNo("Script does not exist", question);
            }

            if (!shouldContinue) {
                throw new IllegalArgumentException("could not find a script with name " + scriptName);
            }

            return;
        }

        GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptSource);
        if (provider == null) {
            throw new IOException("Attempting to run subscript '" + scriptName + "': unable to run this script type.");
        }

        GhidraScript ghidraScript = provider.getScriptInstance(scriptSource, writer);
        ghidraScript.setScriptArgs(scriptArguments);

        if (scriptState == state) {
            updateStateFromVariables();
        }

        ghidraScript.execute(scriptState, monitor, writer);

        if (scriptState == state) {
            loadVariablesFromState();
        }
    }

    private PrintWriter getStdErr() {
        PluginTool tool = state.getTool();
        if (tool != null) {
            ConsoleService console = tool.getService(ConsoleService.class);
            if (console != null) {
                return console.getStdErr();
            }
        }
        return new PrintWriter(System.err, true);
    }

    private PrintWriter getStdOut() {
        PluginTool tool = state.getTool();
        if (tool != null) {
            ConsoleService console = tool.getService(ConsoleService.class);
            if (console != null) {
                return console.getStdOut();
            }
        }
        return new PrintWriter(System.out, true);
    }

}
