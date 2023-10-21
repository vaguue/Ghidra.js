package ghidrajs;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.BlockingQueue;

public class InputReader {
    private final BlockingQueue<String> queue = new LinkedBlockingQueue<>();
    private final BufferedReader reader;

    public InputReader(InputStream inputStream) {
        this.reader = new BufferedReader(new InputStreamReader(inputStream));
    }

    public void startReading() {
        Thread readerThread = new Thread(() -> {
            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    queue.put(line);
                }
            } catch (IOException | InterruptedException e) {
                // handle exception
            }
        });
        readerThread.start();
    }

    public String pollInput() {
        return queue.poll();
    }
}
