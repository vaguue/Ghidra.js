package ghidrajs;

import java.io.PrintWriter;

public class ConsoleLogger {
    private PrintWriter outWriter;
    private PrintWriter errWriter;

    public ConsoleLogger(PrintWriter outWriter, PrintWriter errWriter) {
        this.outWriter = outWriter;
        this.errWriter = errWriter;
    }

    public void log(Object... messages) {
        outWriter.println(joinMessages(messages));
    }

    public void error(Object... messages) {
        errWriter.println(joinMessages(messages));
    }

    private String joinMessages(Object[] messages) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < messages.length; i++) {
            if (i > 0) {
                sb.append(" ");
            }
            sb.append(String.valueOf(messages[i]));
        }
        return sb.toString();
    }
}
