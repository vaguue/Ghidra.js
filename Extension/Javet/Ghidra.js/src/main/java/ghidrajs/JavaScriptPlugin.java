package ghidrajs;

import java.io.IOException;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import javax.swing.ImageIcon;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.JDOMException;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;

import ghidra.framework.Application;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

import ghidra.util.HelpLocation;
import ghidra.util.xml.XmlUtilities;
import ghidra.util.Msg;

import resources.ResourceManager;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.INTERPRETERS,
    shortDescription = "JavaScript Interpreter",
    description = "Provides an interactive JavaScript Interpreter",
    servicesRequired = { InterpreterPanelService.class },
    isSlowInstallation = true
)
public class JavaScriptPlugin extends ProgramPlugin implements InterpreterConnection {
    private String name = "JavaScript";
    private InterpreterConsole console;
    private JavaScriptInterpreter interpreter;

    public static String OPTION_CATEGORY_NAME = "JavaScript interpreter";

    public JavaScriptPlugin(PluginTool tool) {
        super(tool);
                Msg.info(this, "Launching JavaScript plugin");

        String launchActionTitle = "Launch JavaScript interpreter";
        DockingAction launchAction = new DockingAction(launchActionTitle, getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                showConsole();
            }

        };
        launchAction.setToolBarData(new ToolBarData(getIcon(), null));
        launchAction.setDescription(launchActionTitle);
        launchAction.setEnabled(true);
        launchAction.setHelpLocation(new HelpLocation(getTitle(), name));
        tool.addAction(launchAction);
    }

    /**
     * Set up the plugin, including the creation of the interactive interpreter.
     */
    @Override
    public void init() {
      Msg.info(this, "Initializing JavaScript plugin");

      console = getTool().getService(InterpreterPanelService.class).createInterpreterPanel(this, false);
      interpreter = new JavaScriptInterpreter(console, this);
      console.addFirstActivationCallback(() -> {
        interpreter.startInteractiveSession();
      });
    }

    /**
     * Destroys the plugin and any interpreters within.
     */
    @Override
    protected void dispose() {
      interpreter.dispose();
      console.dispose();
      super.dispose();
    }

    /**
     * Get a list of completions for the given command prefix.
     *
     * @param cmd The command to try to complete.
     *
     * @return A list of possible code completions.
     */
    @Override
    public List<CodeCompletion> getCompletions(String cmd) {
        return getInterpreter().getCompletions(cmd, cmd.length());
    }

    /**
     * Get a list of completions for the given command prefix.
     *
     * @param cmd The command to try to complete.
     *
     * @return A list of possible code completions.
     */
    @Override
    public List<CodeCompletion> getCompletions(String cmd, int caretPos) {
        return getInterpreter().getCompletions(cmd, caretPos);
    }

    /**
     * The icon for this plugin.
     */
    @Override
    public ImageIcon getIcon() {
        String imageFilename = "images/" + name.toLowerCase() + ".png";
        return ResourceManager.loadImage(imageFilename);
    }

    /**
     * The title of the plugin.
     */
    @Override
    public String getTitle() {
        return name;
    }

    /**
     * Called whenever the highlight is changed within the CodeBrowser tool.
     */
    @Override
    public void highlightChanged(ProgramSelection sel) {
        getInterpreter().updateHighlight(sel);
    }

    /**
     * Called whenever the location is changed within the CodeBrowser tool.
     */
    @Override
    public void locationChanged(ProgramLocation loc) {
        getInterpreter().updateLocation(loc);
    }

    /**
     * Called whenever a program is activate within the CodeBrowser tool.
     */
    @Override
    public void programActivated(Program program) {
        getInterpreter().updateProgram(program);
    }

    /**
     * Called whenever the selection is changed within the CodeBrowser tool.
     */
    @Override
    public void selectionChanged(ProgramSelection sel) {
        getInterpreter().updateSelection(sel);
    }

    /**
     * Shows the interpreter console.
     */
    public void showConsole() {
      console.show();
    }

    public JavaScriptInterpreter getInterpreter() {
      return interpreter;
    }

}
