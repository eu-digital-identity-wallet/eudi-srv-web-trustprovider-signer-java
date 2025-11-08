/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.rssp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import java.io.File;
import java.util.Date;
import org.springframework.stereotype.Component;

@Component
public class RemovePDFsLifecycle implements SmartLifecycle {
    private static final Logger logger = LoggerFactory.getLogger(RemovePDFsLifecycle.class);

    private Thread removePDFsThread;
    private boolean running = false;
    private final String directory;
    private final int timeSleepThread;
    private final int fileAgeDelete;

    public RemovePDFsLifecycle() {
        this.directory = threadConfig.diretorio;
        this.timeSleepThread = threadConfig.timeSleepThread;
        this.fileAgeDelete = threadConfig.fileAgeDelete;
    }

    @Override
    public void start() {
        removePDFsThread = new Thread(() -> {
            while (running) {
                try {
                    Thread.sleep(timeSleepThread * 1000L);
                    File[] archives = new File(directory).listFiles();
                    if (archives != null) {
                        for (File file : archives) {
                            if (file.isFile() && file.getName().toLowerCase().endsWith(".pdf")) {
                                long diff = new Date().getTime() - file.lastModified();
                                if (diff > fileAgeDelete * 1000L) {
                                    boolean deleted = file.delete();
                                    System.out.println("Removed " + file.getName() + "? "+ deleted);

                                }
                            }
                        }
                    }
                } catch (InterruptedException e) {
                    logger.warn("Interrupted Thread", e);
                    Thread.currentThread().interrupt();
                }
            }
        });
        running = true;
        removePDFsThread.start();
    }

    @Override
    public void stop() {
        running = false;
        if (removePDFsThread != null) {
            removePDFsThread.interrupt();
        }
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    @Override
    public int getPhase() {
        return 0;
    }

    @Override
    public void stop(Runnable callback) {
        stop();
        callback.run();
    }
}
