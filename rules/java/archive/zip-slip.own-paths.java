package com.acme.archives.own;

// java.zip-slip in a file that declares classes of its own named Paths: there Paths.get is the
// project's method, not java.nio.file.Paths.get. OpenGrep runs this file as a third test of the
// rule (zip-slip.yml).

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

class SanitizingPathsExtractor {

    // Keeps only the last name element of the entry.
    static final class Paths {
        static Path get(String name) {
            return Path.of("/srv/extract").resolve(Path.of(name).getFileName());
        }

        static Path under(String name) {
            return Path.of("/srv/extract").resolve(name);
        }
    }

    void unzip(InputStream in, Path dest) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // ok: java.zip-slip
                Files.copy(zis, Paths.get(entry.getName()));
                // ruleid: java.zip-slip
                Files.copy(zis, Paths.under(entry.getName()));
                // ruleid: java.zip-slip
                Files.copy(zis, dest.resolve(entry.getName()));
            }
        }
    }
}

class PlainPathsExtractor {

    // Keeps the whole entry name.
    static final class Paths {
        static Path get(String name) {
            return Path.of("/srv/extract").resolve(name);
        }
    }

    void unzip(InputStream in) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // In a file that declares a class named Paths, Paths.get(name) is not followed
                // (OpenGrep's --taint-intrafile mode reads a get() as a read of its receiver).
                // todoruleid: java.zip-slip
                Files.copy(zis, Paths.get(entry.getName()));
            }
        }
    }
}
