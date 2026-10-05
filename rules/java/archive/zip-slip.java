package com.acme.archives;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.archivers.ar.ArArchiveEntry;
import org.apache.commons.compress.archivers.arj.ArjArchiveEntry;
import org.apache.commons.compress.archivers.cpio.CpioArchiveEntry;
import org.apache.commons.compress.archivers.dump.DumpArchiveEntry;
import org.apache.commons.compress.archivers.jar.JarArchiveEntry;
import org.apache.commons.compress.archivers.sevenz.SevenZArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

// java.util.zip: entries of a ZipInputStream and a ZipFile written under their names.
public class ZipExtractor {

    void unzipStream(InputStream in, File destDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File file = new File(destDir, entry.getName());
                if (entry.isDirectory()) {
                    // ruleid: java.zip-slip
                    file.mkdirs();
                    continue;
                }
                // ruleid: java.zip-slip
                file.getParentFile().mkdirs();
                // ruleid: java.zip-slip
                try (OutputStream out = new BufferedOutputStream(new FileOutputStream(file))) {
                    zis.transferTo(out);
                }
            }
        }
    }

    void unzipFile(File archive, Path dest) throws IOException {
        try (ZipFile zip = new ZipFile(archive)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                // ruleid: java.zip-slip
                Files.copy(zip.getInputStream(entry), dest.resolve(entry.getName()), StandardCopyOption.REPLACE_EXISTING);
                String name = entry.getName();
                Path target = Paths.get(dest.toString(), name);
                // ruleid: java.zip-slip
                Files.createDirectories(target.getParent());
                // ruleid: java.zip-slip
                try (OutputStream out = Files.newOutputStream(target)) {
                    zip.getInputStream(entry).transferTo(out);
                }
                // ruleid: java.zip-slip
                Files.write(dest.resolve("copies").resolve(name), new byte[0]);
                // ruleid: java.zip-slip
                Files.writeString(Path.of(dest.toString(), "meta", name + ".txt"), "x");
            }
        }
    }

    void unzipInferred(InputStream in, String dest) throws IOException {
        var zis = new ZipInputStream(in);
        var entry = zis.getNextEntry();
        while (entry != null) {
            var file = new File(dest + File.separator + entry.getName());
            // ruleid: java.zip-slip
            new FileOutputStream(file).close();
            // ruleid: java.zip-slip
            new FileWriter(dest + "/" + entry.getName() + ".log").close();
            entry = zis.getNextEntry();
        }
    }

    void unzipStreamOfEntries(File archive, Path dest) throws IOException {
        try (ZipFile zip = new ZipFile(archive)) {
            zip.stream().forEach(e -> {
                try {
                    // ruleid: java.zip-slip
                    Files.copy(zip.getInputStream(e), dest.resolve(e.getName()));
                } catch (IOException ex) {
                    throw new IllegalStateException(ex);
                }
            });
        }
    }

    // java.util.jar: jar entries.
    void unjar(File jar, File dest, InputStream in) throws IOException {
        try (JarFile jarFile = new JarFile(jar)) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                // ruleid: java.zip-slip
                FileUtils.copyInputStreamToFile(jarFile.getInputStream(entry), new File(dest, entry.getName()));
            }
        }
        try (JarFile jarFile = new JarFile(jar)) {
            // An entry looked up by a literal name has that name.
            JarEntry manifest = jarFile.getJarEntry("META-INF/MANIFEST.MF");
            // ok: java.zip-slip
            FileUtils.copyInputStreamToFile(jarFile.getInputStream(manifest), new File(dest, manifest.getName()));
            // ok: java.zip-slip
            Files.createDirectories(dest.toPath().resolve(jarFile.getEntry("META-INF/").getName()));
            ZipEntry chosen = jarFile.getEntry(dest.getName());
            // ruleid: java.zip-slip
            Files.createDirectories(dest.toPath().resolve(chosen.getName()));
        }
        try (JarInputStream jis = new JarInputStream(in)) {
            JarEntry entry;
            while ((entry = jis.getNextJarEntry()) != null) {
                // ruleid: java.zip-slip
                FileUtils.copyToFile(jis, new File(dest, entry.getName()));
            }
        }
    }

    // Safe forms: only the last name element, a checked path, a name the code chooses.
    void safe(InputStream in, File destDir, Path dest) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // ok: java.zip-slip
                Files.copy(zis, dest.resolve(Paths.get(entry.getName()).getFileName()));
                Path nameOnly = Path.of(entry.getName()).getFileName();
                // ok: java.zip-slip
                Files.copy(zis, dest.resolve(nameOnly));
                // ok: java.zip-slip
                new FileOutputStream(new File(destDir, new File(entry.getName()).getName())).close();
                // ok: java.zip-slip
                new FileOutputStream(new File(destDir, FilenameUtils.getName(entry.getName()))).close();
                // ok: java.zip-slip
                Files.copy(zis, dest.resolve(java.util.UUID.randomUUID() + ".bin"));
                // The name is only read, logged or used as a key.
                Map<String, byte[]> contents = new HashMap<>();
                // ok: java.zip-slip
                contents.put(entry.getName(), zis.readAllBytes());
                // ok: java.zip-slip
                System.out.println("entry " + entry.getName());
                // ok: java.zip-slip
                File inspected = new File(destDir, entry.getName());
            }
        }
    }

    // A check that the normalized path stays in the destination, and that leaves when it fails.
    void checked(InputStream in, Path dest, File destDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Path target = dest.resolve(entry.getName()).normalize();
                if (!target.startsWith(dest)) {
                    throw new IOException("Entry is outside of the target dir: " + entry.getName());
                }
                // ok: java.zip-slip
                Files.copy(zis, target);

                Path other = dest.resolve(entry.getName());
                if (!other.normalize().startsWith(dest)) {
                    System.err.println("skipping " + entry.getName());
                    continue;
                }
                // ok: java.zip-slip
                Files.createDirectories(other.getParent());

                Path absolute = dest.resolve(entry.getName());
                if (!absolute.toAbsolutePath().normalize().startsWith(dest.toAbsolutePath())) {
                    return;
                }
                // ok: java.zip-slip
                Files.copy(zis, absolute);

                File file = new File(destDir, entry.getName());
                if (!file.getCanonicalPath().startsWith(destDir.getCanonicalPath() + File.separator)) {
                    throw new IOException("Entry is outside of the target dir: " + entry.getName());
                }
                // ok: java.zip-slip
                new FileOutputStream(file).close();

                File viaPath = new File(destDir, entry.getName());
                if (!viaPath.toPath().normalize().startsWith(destDir.toPath())) {
                    throw new IOException("bad entry");
                }
                // ok: java.zip-slip
                viaPath.mkdirs();

                File canonical = new File(destDir, entry.getName());
                String canonicalPath = canonical.getCanonicalPath();
                String canonicalDest = destDir.getCanonicalPath();
                if (!canonicalPath.startsWith(canonicalDest + File.separator)) {
                    throw new IOException("bad entry");
                }
                // ok: java.zip-slip
                new FileOutputStream(canonical).close();

                File canonicalFile = new File(destDir, entry.getName());
                if (!canonicalFile.getCanonicalFile().toPath().startsWith(destDir.getCanonicalFile().toPath())) {
                    break;
                }
                // ok: java.zip-slip
                FileUtils.forceMkdirParent(canonicalFile);

                Path inside = dest.resolve(entry.getName());
                if (inside.normalize().startsWith(dest)) {
                    // ok: java.zip-slip
                    Files.copy(zis, inside);
                }
            }
        }
    }

    // The other spellings of the check: a longer guard body, and the branch where it holds.
    void checkedForms(InputStream in, Path dest, File destDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Path longer = dest.resolve(entry.getName());
                if (!longer.normalize().startsWith(dest)) {
                    System.err.println("bad entry");
                    zis.closeEntry();
                    continue;
                }
                // ok: java.zip-slip
                Files.copy(zis, longer);

                File slash = new File(destDir, entry.getName());
                if (!slash.getCanonicalPath().startsWith(destDir.getCanonicalPath() + "/")) {
                    continue;
                }
                // ok: java.zip-slip
                new FileOutputStream(slash).close();

                Path absolute = dest.resolve(entry.getName());
                if (absolute.toAbsolutePath().normalize().startsWith(dest.toAbsolutePath())) {
                    // ok: java.zip-slip
                    Files.copy(zis, absolute);
                }

                File viaPath = new File(destDir, entry.getName());
                if (viaPath.toPath().normalize().startsWith(destDir.toPath())) {
                    // ok: java.zip-slip
                    viaPath.mkdirs();
                }

                File canonicalFile = new File(destDir, entry.getName());
                if (canonicalFile.getCanonicalFile().toPath().startsWith(destDir.getCanonicalFile().toPath())) {
                    // ok: java.zip-slip
                    canonicalFile.createNewFile();
                }

                Path normalized = dest.resolve(entry.getName()).normalize();
                if (normalized.startsWith(dest)) {
                    // ok: java.zip-slip
                    Files.createDirectories(normalized);
                }

                File canonical = new File(destDir, entry.getName());
                if (canonical.getCanonicalPath().startsWith(destDir.getCanonicalPath() + File.separatorChar)) {
                    // ok: java.zip-slip
                    new FileOutputStream(canonical).close();
                }

                // A normalized variable checked in a branch that has an else.
                Path withElse = dest.resolve(entry.getName()).normalize();
                if (withElse.startsWith(dest)) {
                    System.out.println("inside");
                } else {
                    // ruleid: java.zip-slip
                    Files.copy(zis, withElse);
                }
            }
        }
    }

    // Every spelling of a guard body (one, two or three statements) for every check.
    void guardBodies(InputStream in, Path dest, File destDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                Path n1 = dest.resolve(entry.getName());
                if (!n1.normalize().startsWith(dest)) {
                    continue;
                }
                // ok: java.zip-slip
                Files.copy(zis, n1);

                Path a2 = dest.resolve(entry.getName());
                if (!a2.toAbsolutePath().normalize().startsWith(dest.toAbsolutePath())) {
                    System.err.println("skipped");
                    continue;
                }
                // ok: java.zip-slip
                Files.copy(zis, a2);

                Path a3 = dest.resolve(entry.getName());
                if (!a3.toAbsolutePath().normalize().startsWith(dest.toAbsolutePath())) {
                    System.err.println("skipped");
                    zis.closeEntry();
                    continue;
                }
                // ok: java.zip-slip
                Files.copy(zis, a3);

                File p2 = new File(destDir, entry.getName());
                if (!p2.toPath().normalize().startsWith(destDir.toPath())) {
                    System.err.println("skipped");
                    break;
                }
                // ok: java.zip-slip
                p2.mkdirs();

                File p3 = new File(destDir, entry.getName());
                if (!p3.toPath().normalize().startsWith(destDir.toPath())) {
                    System.err.println("skipped");
                    zis.closeEntry();
                    break;
                }
                // ok: java.zip-slip
                p3.mkdirs();

                File f2 = new File(destDir, entry.getName());
                if (!f2.getCanonicalFile().toPath().startsWith(destDir.getCanonicalFile().toPath())) {
                    System.err.println("skipped");
                    return;
                }
                // ok: java.zip-slip
                f2.createNewFile();

                File f3 = new File(destDir, entry.getName());
                if (!f3.getCanonicalFile().toPath().startsWith(destDir.getCanonicalFile().toPath())) {
                    System.err.println("skipped");
                    zis.closeEntry();
                    return;
                }
                // ok: java.zip-slip
                f3.createNewFile();

                Path v2 = dest.resolve(entry.getName()).normalize();
                if (!v2.startsWith(dest)) {
                    System.err.println("skipped");
                    throw new IOException("bad entry");
                }
                // ok: java.zip-slip
                Files.createDirectories(v2);

                Path v3 = dest.resolve(entry.getName()).normalize();
                if (!v3.startsWith(dest)) {
                    System.err.println("skipped");
                    zis.closeEntry();
                    throw new IOException("bad entry");
                }
                // ok: java.zip-slip
                Files.createDirectories(v3);

                File c2 = new File(destDir, entry.getName());
                if (!c2.getCanonicalPath().startsWith(destDir.getCanonicalPath() + File.separator)) {
                    System.err.println("skipped");
                    continue;
                }
                // ok: java.zip-slip
                new FileOutputStream(c2).close();

                File c3 = new File(destDir, entry.getName());
                if (!c3.getCanonicalPath().startsWith(destDir.getCanonicalPath() + File.separator)) {
                    System.err.println("skipped");
                    zis.closeEntry();
                    continue;
                }
                // ok: java.zip-slip
                new FileOutputStream(c3).close();

                File cv2 = new File(destDir, entry.getName());
                String cv2Path = cv2.getCanonicalPath();
                if (!cv2Path.startsWith(destDir.getCanonicalPath() + File.separator)) {
                    System.err.println("skipped");
                    continue;
                }
                // ok: java.zip-slip
                new FileOutputStream(cv2).close();

                File cv3 = new File(destDir, entry.getName());
                String cv3Path = cv3.getCanonicalPath();
                if (!cv3Path.startsWith(destDir.getCanonicalPath() + File.separator)) {
                    System.err.println("skipped");
                    zis.closeEntry();
                    continue;
                }
                // ok: java.zip-slip
                new FileOutputStream(cv3).close();
            }
        }
    }

    // Only the last name element, through variables.
    void lastNameVariables(InputStream in, Path dest, File destDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                var viaPaths = Paths.get(entry.getName());
                // ok: java.zip-slip
                Files.copy(zis, dest.resolve(viaPaths.getFileName()));
                var viaOf = Path.of(entry.getName());
                // ok: java.zip-slip
                Files.copy(zis, dest.resolve(viaOf.getFileName()));
                Path typed = Paths.get(entry.getName());
                // ok: java.zip-slip
                Files.copy(zis, dest.resolve(typed.getFileName()));
                Path joined = dest.resolve(entry.getName());
                // ok: java.zip-slip
                Files.copy(zis, dest.resolve(joined.getFileName()));
                File named = new File(entry.getName());
                // ok: java.zip-slip
                new FileOutputStream(new File(destDir, named.getName())).close();
            }
        }
    }

    // Checks that do not protect the write.
    void badlyChecked(InputStream in, Path dest, File destDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // Path.startsWith without normalize(): "dest/../x" starts with "dest".
                Path raw = dest.resolve(entry.getName());
                if (!raw.startsWith(dest)) {
                    throw new IOException("bad entry");
                }
                // ruleid: java.zip-slip
                Files.copy(zis, raw);

                // String.startsWith without a separator lets the sibling "dest-evil" through.
                File sibling = new File(destDir, entry.getName());
                if (!sibling.getCanonicalPath().startsWith(destDir.getCanonicalPath())) {
                    throw new IOException("bad entry");
                }
                // ruleid: java.zip-slip
                new FileOutputStream(sibling).close();

                // A suffix that is not a separator.
                File suffixed = new File(destDir, entry.getName());
                if (!suffixed.getCanonicalPath().startsWith(destDir.getCanonicalPath() + destDir.getName())) {
                    throw new IOException("bad entry");
                }
                // ruleid: java.zip-slip
                new FileOutputStream(suffixed).close();

                // The check only logs.
                Path logged = dest.resolve(entry.getName());
                if (!logged.normalize().startsWith(dest)) {
                    System.err.println("suspicious entry " + entry.getName());
                }
                // ruleid: java.zip-slip
                Files.copy(zis, logged);

                // The else branch is where the check failed.
                Path branch = dest.resolve(entry.getName());
                if (branch.normalize().startsWith(dest)) {
                    System.out.println("ok");
                } else {
                    // ruleid: java.zip-slip
                    Files.copy(zis, branch);
                }

                // A check on another path does not protect this one.
                Path first = dest.resolve(entry.getName());
                Path second = dest.resolve("copy").resolve(entry.getName());
                if (!first.normalize().startsWith(dest)) {
                    throw new IOException("bad entry");
                }
                // ruleid: java.zip-slip
                Files.copy(zis, second);

                // A check that leaves on only one of its paths.
                Path partial = dest.resolve(entry.getName());
                if (!partial.normalize().startsWith(dest)) {
                    if (entry.isDirectory()) {
                        throw new IOException("bad directory");
                    }
                }
                // ruleid: java.zip-slip
                Files.copy(zis, partial);
            }
        }
    }

    // Checks the rule does not follow.
    void unfollowedChecks(InputStream in, Path dest, File destDir) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // An ad hoc check of the name: no official doc describes it, and ".." alone does not
                // cover an absolute name.
                if (entry.getName().contains("..")) {
                    continue;
                }
                // todook: java.zip-slip
                Files.copy(zis, dest.resolve(entry.getName()));

                // A check joined with another condition.
                Path joined = dest.resolve(entry.getName());
                if (entry.isDirectory() || !joined.normalize().startsWith(dest)) {
                    continue;
                }
                // todook: java.zip-slip
                Files.copy(zis, joined);

                // A check done by a helper method.
                Path helped = dest.resolve(entry.getName());
                requireInside(helped, dest);
                // todook: java.zip-slip
                Files.copy(zis, helped);

                // A guard body of more than three statements.
                Path verbose = dest.resolve(entry.getName());
                if (!verbose.normalize().startsWith(dest)) {
                    System.err.println("one");
                    System.err.println("two");
                    System.err.println("three");
                    throw new IOException("bad entry");
                }
                // todook: java.zip-slip
                Files.copy(zis, verbose);

                // The true branch of a check that has an else.
                Path both = dest.resolve(entry.getName());
                if (both.normalize().startsWith(dest)) {
                    // todook: java.zip-slip
                    Files.copy(zis, both);
                } else {
                    System.err.println("skipped");
                }
            }
        }
    }

    private static void requireInside(Path path, Path dest) throws IOException {
        if (!path.normalize().startsWith(dest)) {
            throw new IOException("bad entry");
        }
    }

    // An entry obtained through a helper method is not followed.
    void viaHelper(ZipInputStream zis, Path dest) throws IOException {
        ZipEntryHolder holder = new ZipEntryHolder(zis);
        // todoruleid: java.zip-slip
        Files.copy(zis, dest.resolve(holder.nextName()));
    }
}

class ZipEntryHolder {
    private final ZipInputStream zis;

    ZipEntryHolder(ZipInputStream zis) {
        this.zis = zis;
    }

    String nextName() throws IOException {
        return zis.getNextEntry().getName();
    }
}

// Apache Commons Compress: tar and zip archive entries, link targets, the generic stream.
class CompressExtractor {

    void untar(InputStream in, Path dest) throws IOException {
        try (TarArchiveInputStream tar = new TarArchiveInputStream(in)) {
            TarArchiveEntry entry;
            while ((entry = tar.getNextTarEntry()) != null) {
                Path target = dest.resolve(entry.getName());
                if (entry.isSymbolicLink()) {
                    // ruleid: java.zip-slip
                    Files.createSymbolicLink(target, Paths.get(entry.getLinkName()));
                    continue;
                }
                if (entry.isDirectory()) {
                    // ruleid: java.zip-slip
                    Files.createDirectories(target);
                    continue;
                }
                // ruleid: java.zip-slip
                Files.copy(tar, target);
            }
        }
    }

    void unzipCompress(InputStream in, File dest) throws IOException {
        try (ZipArchiveInputStream zip = new ZipArchiveInputStream(in)) {
            ZipArchiveEntry entry;
            while ((entry = zip.getNextZipEntry()) != null) {
                // ruleid: java.zip-slip
                FileUtils.writeByteArrayToFile(new File(dest, entry.getName()), zip.readAllBytes());
            }
        }
    }

    void extractAny(InputStream in, File dest) throws Exception {
        ArchiveInputStream<?> archive = new ArchiveStreamFactory().createArchiveInputStream(in);
        ArchiveEntry entry;
        while ((entry = archive.getNextEntry()) != null) {
            File file = new File(dest, entry.getName());
            // ruleid: java.zip-slip
            FileUtils.forceMkdir(file);
            // ruleid: java.zip-slip
            try (OutputStream out = FileUtils.openOutputStream(file)) {
                archive.transferTo(out);
            }
        }
    }

    void inferredTar(InputStream in, Path dest) throws IOException {
        var tar = new TarArchiveInputStream(in);
        var entry = tar.getNextEntry();
        // ruleid: java.zip-slip
        Files.copy(tar, dest.resolve(entry.getName()));
    }

    // ArchiveEntry.resolveIn (Commons Compress 1.26) refuses names that leave the directory.
    void resolved(InputStream in, Path dest) throws IOException {
        try (TarArchiveInputStream tar = new TarArchiveInputStream(in)) {
            TarArchiveEntry entry;
            while ((entry = tar.getNextEntry()) != null) {
                // ok: java.zip-slip
                Files.copy(tar, entry.resolveIn(dest));
                // ok: java.zip-slip
                Files.copy(tar, dest.resolve(Paths.get(entry.getName()).getFileName()));
            }
        }
    }

    // Look-alikes: getName of a File, of a class, of a request part.
    void lookAlikes(File upload, Path dest, Class<?> type) throws IOException {
        // ok: java.zip-slip
        Files.createDirectories(dest.resolve(upload.getName()));
        // ok: java.zip-slip
        Files.createDirectories(dest.resolve(type.getName()));
        // ok: java.zip-slip
        new FileOutputStream(new File("/var/cache", "index.dat")).close();
    }
}

// Each source and sink spelling on its own line.
class SourceAndSinkForms {

    void entryTypes(JarArchiveEntry jar, SevenZArchiveEntry sevenZ, ArArchiveEntry ar, CpioArchiveEntry cpio,
            ArjArchiveEntry arj, DumpArchiveEntry dump, File dest) throws IOException {
        // ruleid: java.zip-slip
        new FileOutputStream(new File(dest, jar.getName())).close();
        // ruleid: java.zip-slip
        new FileOutputStream(new File(dest, sevenZ.getName())).close();
        // ruleid: java.zip-slip
        new FileOutputStream(new File(dest, ar.getName())).close();
        // ruleid: java.zip-slip
        new FileOutputStream(new File(dest, cpio.getName())).close();
        // ruleid: java.zip-slip
        new FileOutputStream(new File(dest, arj.getName())).close();
        // ruleid: java.zip-slip
        new FileOutputStream(new File(dest, dump.getName())).close();
    }

    // Entries declared with `var` from a stream given by type.
    void typedStreams(ZipInputStream zis, JarInputStream jis, ArchiveInputStream<?> archive, TarArchiveInputStream tar,
            ZipArchiveInputStream zip, Path dest) throws IOException {
        var zipEntry = zis.getNextEntry();
        // ruleid: java.zip-slip
        Files.createDirectories(dest.resolve(zipEntry.getName()));
        var jarEntry = jis.getNextJarEntry();
        // ruleid: java.zip-slip
        Files.createDirectories(dest.resolve(jarEntry.getName()));
        var anyEntry = archive.getNextEntry();
        // ruleid: java.zip-slip
        Files.createDirectories(dest.resolve(anyEntry.getName()));
        var tarEntry = tar.getNextEntry();
        // ruleid: java.zip-slip
        Files.createSymbolicLink(dest.resolve("links").resolve("current"), Paths.get(tarEntry.getLinkName()));
        var zipArchiveEntry = zip.getNextZipEntry();
        // ruleid: java.zip-slip
        Files.createDirectories(dest.resolve(zipArchiveEntry.getName()));
    }

    void rawAndTypedArgument(ArchiveInputStream raw, ArchiveInputStream<TarArchiveEntry> tars, Path dest)
            throws IOException {
        var rawEntry = raw.getNextEntry();
        // ruleid: java.zip-slip
        Files.createDirectories(dest.resolve(rawEntry.getName()));
        var tarEntry = tars.getNextEntry();
        // ruleid: java.zip-slip
        Files.createDirectories(dest.resolve(tarEntry.getName()));
    }

    void createdStream(InputStream in, Path dest) throws IOException {
        var tar = new TarArchiveInputStream(in);
        var entry = tar.getNextTarEntry();
        // ruleid: java.zip-slip
        Files.createSymbolicLink(dest.resolve("links").resolve("latest"), Paths.get(entry.getLinkName()));
    }

    void createdCpio(InputStream in, Path dest) throws IOException {
        var cpio = new org.apache.commons.compress.archivers.cpio.CpioArchiveInputStream(in);
        var entry = cpio.getNextEntry();
        // ruleid: java.zip-slip
        Files.createDirectories(dest.resolve(entry.getName()));
    }

    void tarLinkTarget(TarArchiveEntry entry, Path dest) throws IOException {
        // ruleid: java.zip-slip
        Files.createSymbolicLink(dest.resolve("links").resolve("shared"), Paths.get(entry.getLinkName()));
    }

    // ZipFile and JarFile streams, with block and expression lambdas.
    void entryStreams(ZipFile zip, JarFile jar, Path dest) {
        zip.stream().forEach(e -> {
            // ruleid: java.zip-slip
            dest.resolve(e.getName()).toFile().mkdirs();
        });
        // ruleid: java.zip-slip
        zip.stream().forEach(e -> dest.resolve(e.getName()).toFile().mkdirs());
        jar.stream().forEach(e -> {
            // ruleid: java.zip-slip
            dest.resolve(e.getName()).toFile().mkdirs();
        });
        // ruleid: java.zip-slip
        jar.stream().forEach(e -> dest.resolve(e.getName()).toFile().mkdirs());
    }

    // Moves and links: each path on its own.
    void movesAndLinks(ZipEntry entry, Path dest, Path staged, Path shared) throws IOException {
        // ruleid: java.zip-slip
        Files.move(staged, dest.resolve(entry.getName()));
        // ruleid: java.zip-slip
        Files.createSymbolicLink(dest.resolve(entry.getName()), shared);
        // ruleid: java.zip-slip
        Files.createLink(dest.resolve(entry.getName()), shared);
        // ruleid: java.zip-slip
        Files.createLink(dest.resolve("links").resolve("copy"), dest.resolve(entry.getName()));
    }
}
