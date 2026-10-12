package com.acme.archives;

// java.zip-slip with the java.nio.file types imported on demand (`import java.nio.file.*;`).
// OpenGrep runs this file as a second test of the rule (zip-slip.yml).

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Extracts with the class Paths of java.nio.file (a comment that names "class Paths" declares
 * nothing).
 */
class WildcardImportExtractor {

    void unzip(InputStream in, Path dest) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Path relative = Paths.get(entry.getName());
                // ruleid: java.zip-slip
                Files.copy(zis, dest.resolve(relative));
                String name = entry.getName();
                // ruleid: java.zip-slip
                Files.createDirectories(Paths.get(name));
                // ruleid: java.zip-slip
                Files.write(Paths.get(dest + "/" + entry.getName()), new byte[0]);
                // ruleid: java.zip-slip
                Files.copy(zis, Paths.get(dest.toString(), entry.getName()));

                // ok: java.zip-slip
                Files.copy(zis, dest.resolve(Paths.get(entry.getName()).getFileName()));
                Path nameOnly = Paths.get(entry.getName()).getFileName();
                // ok: java.zip-slip
                Files.copy(zis, dest.resolve(nameOnly));
                Path typed = Paths.get(entry.getName());
                // ok: java.zip-slip
                Files.copy(zis, dest.resolve(typed.getFileName()));
                // ok: java.zip-slip
                Files.copy(zis, Paths.get("/var/lib/app/state.bin"));
                Path checked = dest.resolve(entry.getName()).normalize();
                if (!checked.startsWith(dest)) {
                    throw new IOException("entry outside the destination: " + entry.getName());
                }
                // ok: java.zip-slip
                Files.copy(zis, checked);
            }
        }
    }
}
