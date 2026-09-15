package io.github.codegraph.javaparser;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.eclipse.jdt.core.JavaCore;
import org.eclipse.jdt.core.compiler.IProblem;
import org.eclipse.jdt.core.dom.AST;
import org.eclipse.jdt.core.dom.ASTParser;
import org.eclipse.jdt.core.dom.CompilationUnit;
import org.eclipse.jdt.core.dom.ImportDeclaration;
import org.eclipse.jdt.core.dom.rewrite.ASTRewrite;
import org.eclipse.jdt.core.dom.rewrite.ListRewrite;
import org.eclipse.jface.text.Document;
import org.eclipse.text.edits.TextEdit;

/** JDT-owned Java source transformations used by the remediation sandbox. */
final class SourceEditor {
    private static final int MAX_STDIN_BYTES = 10 * 1024 * 1024;
    private static final int MAX_SOURCE_BYTES = 4 * 1024 * 1024;
    private static final int MAX_STDOUT_BYTES = 16 * 1024 * 1024;
    private static final int MAX_STDERR_BYTES = 8192;
    private static final String REQUEST_SCHEMA = "codegraph-java-edit-request/v1";
    private static final String OUTPUT_SCHEMA = "codegraph-java-edit/v1";
    private static final Gson GSON = new GsonBuilder()
            .disableHtmlEscaping()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .create();

    private SourceEditor() {}

    static void run() {
        try {
            Request request = readRequest(System.in);
            Response response = ensureImport(request);
            String json = GSON.toJson(response);
            if (json.getBytes(StandardCharsets.UTF_8).length > MAX_STDOUT_BYTES) {
                fatal("protocol output cap exceeded");
            }
            try (OutputStreamWriter writer = new OutputStreamWriter(System.out, StandardCharsets.UTF_8)) {
                writer.write(json);
                writer.write('\n');
            }
        } catch (FatalProtocolException ex) {
            boundedStderr("protocol fatal: " + ex.getMessage());
            System.exit(2);
        } catch (Exception ex) {
            boundedStderr(
                    "protocol fatal: internal source editor failure: "
                            + ex.getClass().getSimpleName()
                            + ": "
                            + safe(ex.getMessage()));
            System.exit(3);
        }
    }

    private static Response ensureImport(Request request) {
        String source = decodeUtf8(request.sourceBytes);
        CompilationUnit original = parse(source, request.relativePath, request.languageLevel);
        List<String> originalErrors = blockingProblems(original);
        if (!originalErrors.isEmpty()) {
            return response(request, "REJECTED", request.sourceBytes, "source_not_editable", originalErrors);
        }

        for (Object item : original.imports()) {
            ImportDeclaration existing = (ImportDeclaration) item;
            if (existing.getName().getFullyQualifiedName().equals(request.qualifiedName)
                    && existing.isStatic() == request.isStatic
                    && existing.isOnDemand() == request.onDemand) {
                return response(request, "UNCHANGED", request.sourceBytes, "import_already_present", List.of());
            }
        }

        ImportDeclaration importNode;
        try {
            importNode = original.getAST().newImportDeclaration();
            importNode.setName(original.getAST().newName(request.qualifiedName));
            importNode.setStatic(request.isStatic);
            importNode.setOnDemand(request.onDemand);
        } catch (IllegalArgumentException ex) {
            return response(
                    request,
                    "REJECTED",
                    request.sourceBytes,
                    "invalid_import_name",
                    List.of(safe(ex.getMessage())));
        }

        try {
            ASTRewrite rewrite = ASTRewrite.create(original.getAST());
            ListRewrite imports = rewrite.getListRewrite(original, CompilationUnit.IMPORTS_PROPERTY);
            imports.insertLast(importNode, null);

            Document document = new Document(source);
            TextEdit edit = rewrite.rewriteAST(document, compilerOptions(request.languageLevel));
            edit.apply(document);

            byte[] candidateBytes = document.get().getBytes(StandardCharsets.UTF_8);
            if (candidateBytes.length > MAX_SOURCE_BYTES) {
                return response(
                        request,
                        "REJECTED",
                        request.sourceBytes,
                        "rewritten_source_exceeds_limit",
                        List.of());
            }

            CompilationUnit candidate = parse(document.get(), request.relativePath, request.languageLevel);
            List<String> candidateErrors = blockingProblems(candidate);
            if (!candidateErrors.isEmpty()) {
                return response(request, "REJECTED", request.sourceBytes, "jdt_reparse_failed", candidateErrors);
            }
            return response(request, "APPLIED", candidateBytes, "import_added", List.of());
        } catch (Exception ex) {
            return response(
                    request,
                    "REJECTED",
                    request.sourceBytes,
                    "rewrite_failed",
                    List.of(ex.getClass().getSimpleName() + ": " + safe(ex.getMessage())));
        }
    }

    private static CompilationUnit parse(String source, String relativePath, String languageLevel) {
        ASTParser parser = ASTParser.newParser(AST.JLS25);
        parser.setKind(ASTParser.K_COMPILATION_UNIT);
        parser.setSource(source.toCharArray());
        parser.setUnitName(relativePath);
        parser.setStatementsRecovery(false);
        parser.setBindingsRecovery(false);
        parser.setResolveBindings(false);
        parser.setCompilerOptions(compilerOptions(languageLevel));
        return (CompilationUnit) parser.createAST(null);
    }

    private static List<String> blockingProblems(CompilationUnit unit) {
        List<String> errors = new ArrayList<>();
        for (IProblem problem : unit.getProblems()) {
            if (problem.isError()) {
                errors.add(safe(problem.getMessage()));
            }
        }
        return errors;
    }

    private static Map<String, String> compilerOptions(String level) {
        Map<String, String> options = JavaCore.getOptions();
        String compliance = "8".equals(level) ? JavaCore.VERSION_1_8 : level;
        options.put(JavaCore.COMPILER_SOURCE, compliance);
        options.put(JavaCore.COMPILER_COMPLIANCE, compliance);
        options.put(JavaCore.COMPILER_CODEGEN_TARGET_PLATFORM, compliance);
        options.put(JavaCore.COMPILER_PB_ENABLE_PREVIEW_FEATURES, JavaCore.DISABLED);
        options.put(JavaCore.COMPILER_PB_REPORT_PREVIEW_FEATURES, JavaCore.IGNORE);
        return options;
    }

    private static Response response(
            Request request,
            String status,
            byte[] sourceBytes,
            String reason,
            List<String> errors) {
        Response response = new Response();
        response.schemaVersion = OUTPUT_SCHEMA;
        response.operation = "ensure_import";
        response.status = status;
        response.relativePath = request.relativePath;
        response.qualifiedName = request.qualifiedName;
        response.isStatic = request.isStatic;
        response.onDemand = request.onDemand;
        response.sourceSha256Before = sha256(request.sourceBytes);
        response.sourceSha256After = sha256(sourceBytes);
        response.sourceByteLength = sourceBytes.length;
        response.sourceBase64 = Base64.getEncoder().encodeToString(sourceBytes);
        response.reason = reason;
        response.errors = errors;
        return response;
    }

    private static Request readRequest(InputStream input) throws IOException {
        byte[] raw = readBounded(input, MAX_STDIN_BYTES + 1);
        if (raw.length > MAX_STDIN_BYTES) {
            fatal("stdin JSON exceeds 10MiB cap");
        }
        String json;
        try {
            json = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw))
                    .toString();
        } catch (CharacterCodingException ex) {
            fatal("stdin must be strict UTF-8");
            return null;
        }

        Request request;
        try {
            request = GSON.fromJson(json, Request.class);
        } catch (JsonParseException ex) {
            fatal("invalid JSON request");
            return null;
        }
        if (request == null || !REQUEST_SCHEMA.equals(request.schemaVersion)) {
            fatal("schema_version must be " + REQUEST_SCHEMA);
        }
        if (!"ensure_import".equals(request.operation)) {
            fatal("operation must be ensure_import");
        }
        if (request.relativePath == null || request.relativePath.isBlank()) {
            fatal("relative_path is required");
        }
        if (request.relativePath.indexOf('\0') >= 0) {
            fatal("relative_path must not contain NUL bytes");
        }
        Path relativePath = Path.of(request.relativePath);
        if (relativePath.isAbsolute() || request.relativePath.equals(".")) {
            fatal("relative_path must be a non-absolute path without '..' segments");
        }
        for (Path segment : relativePath) {
            if (segment.toString().equals("..")) {
                fatal("relative_path must be a non-absolute path without '..' segments");
            }
        }
        if (request.sourceBase64 == null) {
            fatal("source_base64 is required");
        }
        try {
            request.sourceBytes = Base64.getDecoder().decode(request.sourceBase64);
        } catch (IllegalArgumentException ex) {
            fatal("source_base64 is invalid");
        }
        if (request.sourceBytes.length > MAX_SOURCE_BYTES) {
            fatal("decoded source exceeds 4MiB cap");
        }
        decodeUtf8(request.sourceBytes);
        if (request.languageLevel == null || !isSupportedLanguageLevel(request.languageLevel)) {
            fatal("language_level must be a Java release from 8 through 25");
        }
        if (request.qualifiedName == null || request.qualifiedName.isBlank()) {
            fatal("qualified_name is required");
        }
        return request;
    }

    private static String decodeUtf8(byte[] sourceBytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(sourceBytes))
                    .toString();
        } catch (CharacterCodingException ex) {
            throw new FatalProtocolException("source_base64 must decode to strict UTF-8 Java source");
        }
    }

    private static boolean isSupportedLanguageLevel(String level) {
        try {
            int value = Integer.parseInt(level);
            return value >= 8 && value <= 25;
        } catch (NumberFormatException ex) {
            return false;
        }
    }

    private static byte[] readBounded(InputStream input, int cap) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(cap, 8192));
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            total += read;
            if (total > cap) {
                out.write(buffer, 0, read - (total - cap));
                break;
            }
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static String sha256(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return hex(digest.digest(bytes));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }

    private static void fatal(String message) {
        throw new FatalProtocolException(message);
    }

    private static void boundedStderr(String message) {
        String clean = safe(message);
        byte[] bytes = (clean + System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_STDERR_BYTES) {
            clean = new String(bytes, 0, MAX_STDERR_BYTES - 4, StandardCharsets.UTF_8) + "...";
        }
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(System.err, StandardCharsets.UTF_8));
        writer.println(clean);
        writer.flush();
    }

    private static String safe(String value) {
        if (value == null) return "";
        return value.replaceAll("[\\r\\n\\t]+", " ");
    }

    private static final class Request {
        String schemaVersion;
        String operation;
        String relativePath;
        String sourceBase64;
        String languageLevel;
        String qualifiedName;
        boolean isStatic;
        boolean onDemand;
        byte[] sourceBytes;
    }

    private static final class Response {
        String schemaVersion;
        String operation;
        String status;
        String relativePath;
        String qualifiedName;
        boolean isStatic;
        boolean onDemand;
        String sourceSha256Before;
        String sourceSha256After;
        int sourceByteLength;
        String sourceBase64;
        String reason;
        List<String> errors;
    }

    private static final class FatalProtocolException extends RuntimeException {
        FatalProtocolException(String message) {
            super(message);
        }
    }
}
