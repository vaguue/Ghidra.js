package ghidrajs;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraScriptProvider;

public class JavaScriptProvider extends GhidraScriptProvider {

    @Override
    public String getDescription() {
        return "JavaScript";
    }

    @Override
    public String getExtension() {
        return ".js";
    }

    @Override
    public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
            throws GhidraScriptLoadException {
        GhidraScript script = new JavaScriptProgram();
        script.setSourceFile(sourceFile);
        return script;
    }

    @Override
    public void createNewScript(ResourceFile newScript, String category) throws IOException {
        PrintWriter writer = new PrintWriter(new FileWriter(newScript.getFile(false)));
        writeHeader(writer, category);
        writer.println("");
        writeBody(writer);
        writer.println("");
        writer.close();
    }

    @Override
    public String getCommentCharacter() {
        return "//";
    }

}
