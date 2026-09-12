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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.eclipse.jdt.core.JavaCore;
import org.eclipse.jdt.core.compiler.IProblem;
import org.eclipse.jdt.core.dom.AST;
import org.eclipse.jdt.core.dom.ASTNode;
import org.eclipse.jdt.core.dom.ASTParser;
import org.eclipse.jdt.core.dom.ASTVisitor;
import org.eclipse.jdt.core.dom.AbstractTypeDeclaration;
import org.eclipse.jdt.core.dom.Annotation;
import org.eclipse.jdt.core.dom.AnnotationTypeDeclaration;
import org.eclipse.jdt.core.dom.AnonymousClassDeclaration;
import org.eclipse.jdt.core.dom.Block;
import org.eclipse.jdt.core.dom.BodyDeclaration;
import org.eclipse.jdt.core.dom.ClassInstanceCreation;
import org.eclipse.jdt.core.dom.CompilationUnit;
import org.eclipse.jdt.core.dom.ConstructorInvocation;
import org.eclipse.jdt.core.dom.EnumDeclaration;
import org.eclipse.jdt.core.dom.Expression;
import org.eclipse.jdt.core.dom.FieldAccess;
import org.eclipse.jdt.core.dom.FieldDeclaration;
import org.eclipse.jdt.core.dom.IBinding;
import org.eclipse.jdt.core.dom.IMethodBinding;
import org.eclipse.jdt.core.dom.ITypeBinding;
import org.eclipse.jdt.core.dom.IVariableBinding;
import org.eclipse.jdt.core.dom.ImportDeclaration;
import org.eclipse.jdt.core.dom.Initializer;
import org.eclipse.jdt.core.dom.MethodDeclaration;
import org.eclipse.jdt.core.dom.MethodInvocation;
import org.eclipse.jdt.core.dom.Modifier;
import org.eclipse.jdt.core.dom.Name;
import org.eclipse.jdt.core.dom.PackageDeclaration;
import org.eclipse.jdt.core.dom.QualifiedName;
import org.eclipse.jdt.core.dom.RecordDeclaration;
import org.eclipse.jdt.core.dom.SimpleName;
import org.eclipse.jdt.core.dom.SingleVariableDeclaration;
import org.eclipse.jdt.core.dom.SuperConstructorInvocation;
import org.eclipse.jdt.core.dom.SuperFieldAccess;
import org.eclipse.jdt.core.dom.SuperMethodInvocation;
import org.eclipse.jdt.core.dom.Type;
import org.eclipse.jdt.core.dom.TypeDeclaration;
import org.eclipse.jdt.core.dom.VariableDeclarationFragment;

public final class Main {
    private static final int MAX_STDIN_BYTES = 10 * 1024 * 1024;
    private static final int MAX_SOURCE_BYTES = 4 * 1024 * 1024;
    private static final int MAX_STDOUT_BYTES = 16 * 1024 * 1024;
    private static final int MAX_STDERR_BYTES = 8192;
    private static final String REQUEST_SCHEMA = "codegraph-java-request/v1";
    private static final String OUTPUT_SCHEMA = "codegraph-java/v1";
    private static final String JDT_VERSION = "3.47.0";
    private static final String ADAPTER_VERSION = "0.1.0";
    private static final Gson GSON = new GsonBuilder()
            .disableHtmlEscaping()
            .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .create();

    private Main() {}

    public static void main(String[] args) {
        try {
            Request request = readRequest(System.in);
            ParsedJavaFileDto dto = new Extractor(request).parse();
            String json = GSON.toJson(dto);
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
            boundedStderr("protocol fatal: internal parser failure: " + ex.getClass().getSimpleName() + ": " + safe(ex.getMessage()));
            System.exit(3);
        }
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
        if (request.relativePath == null || request.relativePath.isBlank()) {
            fatal("relative_path is required");
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
        if (request.languageLevel == null || request.languageLevel.isBlank()) {
            fatal("language_level is required");
        }
        if (!isSupportedLanguageLevel(request.languageLevel)) {
            fatal("language_level must be a Java release from 8 through 25");
        }
        request.classpath = request.classpath == null ? List.of() : request.classpath;
        request.sourceRoots = request.sourceRoots == null ? List.of() : request.sourceRoots;
        for (String path : request.classpath) {
            if (path == null || !path.startsWith("/")) fatal("classpath entries must be absolute paths");
        }
        for (String path : request.sourceRoots) {
            if (path == null || !path.startsWith("/")) fatal("source_roots entries must be absolute paths");
        }
        return request;
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

    private static final class Extractor {
        private final Request request;
        private final String source;
        private final char[] chars;
        private final Utf8Index utf8Index;
        private final List<DiagnosticDto> diagnostics = new ArrayList<>();
        private final List<TypeDeclarationDto> types = new ArrayList<>();
        private final List<FieldDeclarationDto> fields = new ArrayList<>();
        private final List<MethodDeclarationDto> methods = new ArrayList<>();
        private final Map<String, String> explicitImports = new HashMap<>();
        private final Set<String> onDemandImports = new HashSet<>();
        private final Map<String, Set<String>> fieldNamesByType = new HashMap<>();
        private final Map<String, String> parentTypeByType = new HashMap<>();
        private final ArrayDeque<TypeFrame> typeStack = new ArrayDeque<>();
        private CompilationUnit cu;
        private int anonymousOrdinal = 0;
        private int localOrdinal = 0;

        Extractor(Request request) {
            this.request = request;
            try {
                this.source = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(request.sourceBytes))
                        .toString();
            } catch (CharacterCodingException ex) {
                throw new FatalProtocolException("source_base64 must decode to strict UTF-8 Java source");
            }
            this.chars = source.toCharArray();
            this.utf8Index = new Utf8Index(source);
        }

        ParsedJavaFileDto parse() {
            ASTParser parser = ASTParser.newParser(AST.JLS25);
            parser.setKind(ASTParser.K_COMPILATION_UNIT);
            parser.setSource(chars);
            parser.setUnitName(request.relativePath);
            parser.setStatementsRecovery(false);
            parser.setBindingsRecovery(false);
            parser.setCompilerOptions(compilerOptions(request.languageLevel));
            parser.setResolveBindings(request.resolveBindings);
            if (request.resolveBindings) {
                parser.setEnvironment(
                        request.classpath.toArray(String[]::new),
                        request.sourceRoots.toArray(String[]::new),
                        null,
                        true);
            }
            cu = (CompilationUnit) parser.createAST(null);
            collectProblems();
            List<ImportDto> imports = collectImports();
            cu.accept(new ASTVisitor() {
                @Override public boolean visit(TypeDeclaration node) { collectType(node); return false; }
                @Override public boolean visit(EnumDeclaration node) { collectType(node); return false; }
                @Override public boolean visit(AnnotationTypeDeclaration node) { collectType(node); return false; }
                @Override public boolean visit(RecordDeclaration node) { collectType(node); return false; }
            });
            sortByRange(types);
            sortByRange(fields);
            sortByRange(methods);

            ParsedJavaFileDto dto = new ParsedJavaFileDto();
            dto.schemaVersion = OUTPUT_SCHEMA;
            dto.provenance = provenance();
            dto.relativePath = request.relativePath;
            PackageDeclaration pkg = cu.getPackage();
            dto.packageName = pkg == null ? null : pkg.getName().getFullyQualifiedName();
            dto.imports = imports;
            dto.sourceSha256 = sha256(request.sourceBytes);
            dto.sourceByteLength = request.sourceBytes.length;
            dto.diagnostics = diagnostics;
            dto.coverage = coverage();
            if ("failed".equals(dto.coverage)) {
                dto.types = List.of();
                dto.fields = List.of();
                dto.methods = List.of();
            } else {
                dto.types = types;
                dto.fields = fields;
                dto.methods = methods;
            }
            return dto;
        }

        private Map<String, String> compilerOptions(String level) {
            Map<String, String> options = JavaCore.getOptions();
            String compliance = complianceLevel(level);
            options.put(JavaCore.COMPILER_SOURCE, compliance);
            options.put(JavaCore.COMPILER_COMPLIANCE, compliance);
            options.put(JavaCore.COMPILER_CODEGEN_TARGET_PLATFORM, compliance);
            options.put(JavaCore.COMPILER_PB_ENABLE_PREVIEW_FEATURES, JavaCore.DISABLED);
            options.put(JavaCore.COMPILER_PB_REPORT_PREVIEW_FEATURES, JavaCore.IGNORE);
            return options;
        }

        private String complianceLevel(String level) {
            return "8".equals(level) ? JavaCore.VERSION_1_8 : level;
        }

        private JavaParserProvenanceDto provenance() {
            JavaParserProvenanceDto dto = new JavaParserProvenanceDto();
            dto.backend = "eclipse-jdt";
            dto.backendVersion = JDT_VERSION;
            dto.adapterVersion = ADAPTER_VERSION;
            dto.languageLevel = request.languageLevel;
            dto.resolutionEnabled = request.resolveBindings;
            dto.classpathFingerprint = classpathFingerprint();
            return dto;
        }

        private String classpathFingerprint() {
            if (request.classpath.isEmpty() && request.sourceRoots.isEmpty()) return null;
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                for (String entry : request.classpath) updateFingerprintEntry(digest, "classpath", entry);
                for (String entry : request.sourceRoots) updateFingerprintEntry(digest, "source_root", entry);
                return "sha256:" + hex(digest.digest());
            } catch (IOException | NoSuchAlgorithmException ex) {
                throw new FatalProtocolException("classpath_fingerprint failed: " + safe(ex.getMessage()));
            }
        }

        private void collectProblems() {
            for (IProblem problem : cu.getProblems()) {
                DiagnosticDto dto = new DiagnosticDto();
                boolean symbolOnly = isSymbolProblem(problem);
                dto.severity = problem.isError() && !symbolOnly ? "error" : "warning";
                dto.phase = symbolOnly ? "symbol" : "parse";
                dto.code = "jdt." + problem.getID();
                dto.message = safe(problem.getMessage());
                dto.range = range(problem.getSourceStart(), problem.getSourceEnd() - problem.getSourceStart() + 1, "problem source position unavailable");
                dto.coverageImpact = problem.isError() && !symbolOnly ? "file_failed" : "file_partial";
                diagnostics.add(dto);
            }
        }

        private boolean isSymbolProblem(IProblem problem) {
            String message = problem.getMessage() == null ? "" : problem.getMessage().toLowerCase(Locale.ROOT);
            return request.resolveBindings && (
                message.contains("cannot be resolved") ||
                message.contains("is not a type") ||
                message.contains("refers to the missing type") ||
                message.contains("missing type") ||
                message.contains("the hierarchy of the type") ||
                message.contains("must override or implement") ||
                message.contains("supertype method")
            );
        }

        private List<ImportDto> collectImports() {
            List<ImportDto> result = new ArrayList<>();
            for (Object item : cu.imports()) {
                ImportDeclaration imp = (ImportDeclaration) item;
                String name = imp.getName().getFullyQualifiedName();
                if (imp.isOnDemand()) {
                    onDemandImports.add(name);
                } else {
                    explicitImports.put(simpleName(name), name);
                }
                ImportDto dto = new ImportDto();
                dto.name = name;
                dto.isStatic = imp.isStatic();
                dto.onDemand = imp.isOnDemand();
                dto.range = range(imp);
                result.add(dto);
            }
            return result;
        }

        private void collectType(AbstractTypeDeclaration node) {
            TypeFrame parent = typeStack.peek();
            TypeFrame frame = typeFrame(node, parent, null);
            typeStack.push(frame);
            TypeDeclarationDto dto = typeDto(node, frame, parent);
            types.add(dto);
            collectFieldsAndMethods(node, dto);
            for (Object child : bodyDeclarations(node)) {
                if (child instanceof TypeDeclaration n) collectType(n);
                else if (child instanceof EnumDeclaration n) collectType(n);
                else if (child instanceof AnnotationTypeDeclaration n) collectType(n);
                else if (child instanceof RecordDeclaration n) collectType(n);
            }
            typeStack.pop();
        }

        private void collectAnonymous(AnonymousClassDeclaration node, TypeFrame parent, ClassInstanceCreation creation) {
            TypeFrame frame = typeFrame(null, parent, creation);
            typeStack.push(frame);
            TypeDeclarationDto dto = new TypeDeclarationDto();
            dto.sourceKey = frame.sourceKey;
            dto.kind = "anonymous";
            dto.name = frame.name;
            dto.qualifiedName = frame.qualifiedName;
            dto.binaryName = null;
            dto.nestingPath = frame.nestingPath;
            dto.enclosingTypeSourceKey = parent == null ? null : parent.sourceKey;
            dto.localOrdinal = frame.localOrdinal;
            if (parent != null) parentTypeByType.put(dto.sourceKey, parent.sourceKey);
            dto.bodyDeclarationKinds = bodyKinds(node.bodyDeclarations());
            dto.declarationRange = range(node);
            BindingFacts binding = typeBindingFacts(creation == null ? null : creation.resolveTypeBinding());
            applyTypeBinding(dto, binding);
            types.add(dto);
            collectBodyDeclarations(node.bodyDeclarations(), dto);
            typeStack.pop();
        }

        private TypeDeclarationDto typeDto(AbstractTypeDeclaration node, TypeFrame frame, TypeFrame parent) {
            TypeDeclarationDto dto = new TypeDeclarationDto();
            dto.sourceKey = frame.sourceKey;
            dto.kind = typeKind(node);
            dto.name = node.getName().getIdentifier();
            dto.qualifiedName = frame.qualifiedName;
            ITypeBinding binding = resolveTypeBinding(node);
            dto.binaryName = binding == null || binding.isRecovered() ? null : binding.getBinaryName();
            dto.nestingPath = frame.nestingPath;
            dto.enclosingTypeSourceKey = parent == null ? null : parent.sourceKey;
            dto.localOrdinal = frame.localOrdinal;
            if (parent != null) parentTypeByType.put(dto.sourceKey, parent.sourceKey);
            dto.bodyDeclarationKinds = typeBodyKinds(node);
            dto.modifiers = modifiers(node.modifiers());
            dto.annotationNames = annotations(node.modifiers());
            if (node instanceof TypeDeclaration td && td.getSuperclassType() != null) {
                dto.superclass = typeRef(td.getSuperclassType());
            }
            if (node instanceof TypeDeclaration td) {
                dto.interfaces = typeRefs(td.superInterfaceTypes());
            } else if (node instanceof RecordDeclaration rd) {
                dto.interfaces = typeRefs(rd.superInterfaceTypes());
            } else if (node instanceof EnumDeclaration ed) {
                dto.interfaces = typeRefs(ed.superInterfaceTypes());
            }
            dto.declarationRange = range(node);
            dto.nameRange = range(node.getName());
            applyTypeBinding(dto, typeBindingFacts(binding));
            return dto;
        }

        private void collectFieldsAndMethods(AbstractTypeDeclaration node, TypeDeclarationDto owner) {
            if (node instanceof RecordDeclaration record) collectRecordComponents(record, owner);
            collectBodyDeclarations(bodyDeclarations(node), owner);
            collectImplicitConstructors(node, owner);
        }

        private void collectBodyDeclarations(List<?> declarations, TypeDeclarationDto owner) {
            for (Object child : declarations) {
                if (child instanceof FieldDeclaration field) collectField(field, owner);
                else if (child instanceof MethodDeclaration method) collectMethod(method, owner, method.isCompactConstructor());
                else if (child instanceof Initializer initializer) addRecoveredDiagnosticIfNeeded(initializer);
            }
        }

        private void collectRecordComponents(RecordDeclaration node, TypeDeclarationDto owner) {
            for (Object componentObj : node.recordComponents()) {
                if (!(componentObj instanceof SingleVariableDeclaration component)) continue;
                FieldDeclarationDto dto = new FieldDeclarationDto();
                dto.sourceKey = owner.sourceKey + "#field:" + component.getName().getIdentifier() + "#range:" + byteSpan(component);
                dto.declaringTypeSourceKey = owner.sourceKey;
                dto.name = component.getName().getIdentifier();
                dto.type = typeRef(component.getType());
                dto.modifiers = modifiers(component.modifiers());
                dto.annotationNames = annotations(component.modifiers());
                dto.declarationRange = range(component);
                dto.nameRange = range(component.getName());
                dto.hasInitializer = false;
                applyVariableBinding(dto, component.resolveBinding());
                if ("resolved".equals(dto.resolutionStatus) && "unknown".equals(dto.bindingOrigin)) {
                    dto.bindingOrigin = "source";
                }
                fields.add(dto);
                fieldNamesByType.computeIfAbsent(owner.sourceKey, ignored -> new HashSet<>()).add(dto.name);
            }
        }

        private void collectField(FieldDeclaration node, TypeDeclarationDto owner) {
            for (Object fragObj : node.fragments()) {
                VariableDeclarationFragment frag = (VariableDeclarationFragment) fragObj;
                FieldDeclarationDto dto = new FieldDeclarationDto();
                dto.sourceKey = owner.sourceKey + "#field:" + frag.getName().getIdentifier() + "#range:" + byteSpan(node);
                dto.declaringTypeSourceKey = owner.sourceKey;
                dto.name = frag.getName().getIdentifier();
                dto.type = typeRef(node.getType());
                dto.modifiers = modifiers(node.modifiers());
                dto.annotationNames = annotations(node.modifiers());
                dto.declarationRange = range(node);
                dto.nameRange = range(frag.getName());
                dto.initializerRange = frag.getInitializer() == null ? null : range(frag.getInitializer());
                dto.hasInitializer = frag.getInitializer() != null;
                IVariableBinding binding = frag.resolveBinding();
                applyVariableBinding(dto, binding);
                fields.add(dto);
                fieldNamesByType.computeIfAbsent(owner.sourceKey, ignored -> new HashSet<>()).add(dto.name);
            }
        }

        private void collectMethod(MethodDeclaration node, TypeDeclarationDto owner, boolean compact) {
            MethodDeclarationDto dto = baseMethodDto(node, owner, compact ? "compact_constructor" : (node.isConstructor() ? "constructor" : "method"));
            dto.name = node.isConstructor() ? owner.name : node.getName().getIdentifier();
            dto.returnType = node.isConstructor() ? null : typeRef(node.getReturnType2());
            IMethodBinding binding = node.resolveBinding();
            dto.parameters = compact && node.getParent() instanceof RecordDeclaration record
                    ? recordConstructorParameters(record, binding)
                    : parameters(node.parameters());
            dto.thrownTypes = typeRefs(node.thrownExceptionTypes());
            dto.syntacticParameterTypes = syntacticParameterTypes(dto.parameters);
            fillSignatures(dto, owner);
            applyMethodBinding(dto, binding);
            Block body = node.getBody();
            dto.nameRange = range(node.getName());
            dto.bodyRange = body == null ? null : range(body);
            if (body != null) collectMethodBody(body, dto, owner);
            methods.add(dto);
        }

        private MethodDeclarationDto baseMethodDto(BodyDeclaration node, TypeDeclarationDto owner, String kind) {
            MethodDeclarationDto dto = new MethodDeclarationDto();
            dto.declaringTypeSourceKey = owner.sourceKey;
            dto.declaringTypeQualifiedName = owner.qualifiedName;
            dto.kind = kind;
            dto.modifiers = modifiers(node.modifiers());
            dto.annotationNames = annotations(node.modifiers());
            dto.declarationRange = range(node);
            dto.declarationKey = request.relativePath + ":" + dto.declarationRange.startByte + ":" + dto.declarationRange.endByte;
            return dto;
        }

        private void collectImplicitConstructors(AbstractTypeDeclaration node, TypeDeclarationDto owner) {
            if (!request.resolveBindings || hasExplicitConstructor(node)) return;
            ITypeBinding typeBinding = resolveTypeBinding(node);
            if (typeBinding == null || typeBinding.isRecovered()) return;
            for (IMethodBinding methodBinding : typeBinding.getDeclaredMethods()) {
                if (!methodBinding.isConstructor()) continue;
                if (!methodBinding.isDefaultConstructor() && !methodBinding.isCanonicalConstructor()) continue;
                MethodDeclarationDto dto = new MethodDeclarationDto();
                dto.declaringTypeSourceKey = owner.sourceKey;
                dto.declaringTypeQualifiedName = owner.qualifiedName;
                dto.kind = "constructor";
                dto.name = owner.name;
                dto.modifiers = List.of();
                dto.annotationNames = List.of();
                dto.declarationRange = absentRange("JDT implicit constructor has no source declaration");
                dto.declarationKey = request.relativePath + ":implicit-constructor:" + owner.qualifiedName;
                dto.parameters = implicitConstructorParameters(node, methodBinding);
                dto.thrownTypes = List.of();
                dto.syntacticParameterTypes = syntacticParameterTypes(dto.parameters);
                fillSignatures(dto, owner);
                applyMethodBinding(dto, methodBinding);
                methods.add(dto);
            }
        }

        private boolean hasExplicitConstructor(AbstractTypeDeclaration node) {
            for (Object child : bodyDeclarations(node)) {
                if (child instanceof MethodDeclaration method && method.isConstructor()) return true;
            }
            return false;
        }

        private List<ParameterDto> implicitConstructorParameters(AbstractTypeDeclaration node, IMethodBinding binding) {
            ITypeBinding[] parameterTypes = binding.getParameterTypes();
            List<?> recordComponents = node instanceof RecordDeclaration rd ? rd.recordComponents() : List.of();
            List<ParameterDto> result = new ArrayList<>();
            for (int i = 0; i < parameterTypes.length; i++) {
                ParameterDto dto = new ParameterDto();
                dto.type = typeRef(parameterTypes[i]);
                if (i < recordComponents.size() && recordComponents.get(i) instanceof SingleVariableDeclaration component) {
                    dto.name = component.getName().getIdentifier();
                    dto.range = range(component);
                    if (dto.type != null) dto.type.source = component.getType().toString();
                } else {
                    dto.name = "arg" + i;
                }
                result.add(dto);
            }
            return result;
        }

        private List<ParameterDto> recordConstructorParameters(RecordDeclaration record, IMethodBinding binding) {
            List<?> recordComponents = record.recordComponents();
            ITypeBinding[] parameterTypes = binding == null || binding.isRecovered() ? new ITypeBinding[0] : binding.getParameterTypes();
            List<ParameterDto> result = new ArrayList<>();
            for (int i = 0; i < recordComponents.size(); i++) {
                if (!(recordComponents.get(i) instanceof SingleVariableDeclaration component)) continue;
                ParameterDto dto = new ParameterDto();
                dto.name = component.getName().getIdentifier();
                dto.type = i < parameterTypes.length ? typeRef(parameterTypes[i]) : typeRef(component.getType());
                if (dto.type != null) {
                    dto.type.source = component.getType().toString();
                    dto.type.varargs = component.isVarargs();
                }
                result.add(dto);
            }
            return result;
        }

        private void collectMethodBody(Block body, MethodDeclarationDto method, TypeDeclarationDto owner) {
            MethodBodyCollector collector = new MethodBodyCollector(method, owner);
            body.accept(collector);
            method.invocations = collector.invocations;
            method.fieldUses = collector.fieldUses;
        }

        private final class MethodBodyCollector extends ASTVisitor {
            private final MethodDeclarationDto method;
            private final TypeDeclarationDto owner;
            private final List<InvocationDto> invocations = new ArrayList<>();
            private final List<FieldUseDto> fieldUses = new ArrayList<>();

            MethodBodyCollector(MethodDeclarationDto method, TypeDeclarationDto owner) {
                this.method = method;
                this.owner = owner;
            }

            @Override public boolean visit(TypeDeclaration node) { collectType(node); return false; }
            @Override public boolean visit(EnumDeclaration node) { collectType(node); return false; }
            @Override public boolean visit(AnnotationTypeDeclaration node) { collectType(node); return false; }
            @Override public boolean visit(RecordDeclaration node) { collectType(node); return false; }
            @Override public boolean visit(AnonymousClassDeclaration node) {
                ASTNode parent = node.getParent();
                collectAnonymous(node, typeStack.peek(), parent instanceof ClassInstanceCreation cic ? cic : null);
                return false;
            }

            @Override public boolean visit(MethodInvocation node) {
                InvocationDto dto = invocationBase("method", node.getName().getIdentifier(), node, node.arguments());
                Expression expression = node.getExpression();
                dto.qualifierSource = expression == null ? null : sourceSlice(expression);
                dto.terminalChainMember = !(node.getParent() instanceof MethodInvocation parent && parent.getExpression() == node);
                dto.chainMembers = chainMembers(node);
                applyInvocationBinding(dto, node.resolveMethodBinding());
                invocations.add(dto);
                return true;
            }

            @Override public boolean visit(SuperMethodInvocation node) {
                InvocationDto dto = invocationBase("method", node.getName().getIdentifier(), node, node.arguments());
                dto.qualifierSource = "super";
                dto.terminalChainMember = true;
                applyInvocationBinding(dto, node.resolveMethodBinding());
                invocations.add(dto);
                return true;
            }

            @Override public boolean visit(ClassInstanceCreation node) {
                String name = node.getType() == null ? "<anonymous>" : node.getType().toString();
                InvocationDto dto = invocationBase("constructor", simpleName(name), node, node.arguments());
                Expression expression = node.getExpression();
                dto.qualifierSource = expression == null ? null : sourceSlice(expression);
                dto.terminalChainMember = true;
                applyInvocationBinding(dto, node.resolveConstructorBinding());
                invocations.add(dto);
                return true;
            }

            @Override public boolean visit(ConstructorInvocation node) {
                InvocationDto dto = invocationBase("constructor", "this", node, node.arguments());
                dto.terminalChainMember = true;
                applyInvocationBinding(dto, node.resolveConstructorBinding());
                invocations.add(dto);
                return true;
            }

            @Override public boolean visit(SuperConstructorInvocation node) {
                InvocationDto dto = invocationBase("constructor", "super", node, node.arguments());
                dto.terminalChainMember = true;
                applyInvocationBinding(dto, node.resolveConstructorBinding());
                invocations.add(dto);
                return true;
            }

            @Override public boolean visit(SimpleName node) {
                if (isDeclarationName(node)) return true;
                IBinding binding = node.resolveBinding();
                if (binding instanceof IVariableBinding variable && variable.isField()) {
                    FieldUseDto dto = new FieldUseDto();
                    dto.name = node.getIdentifier();
                    dto.range = range(node);
                    if (variable.isRecovered()) {
                        dto.resolutionStatus = "unresolved";
                        dto.unresolvedReason = "recovered field binding";
                        dto.bindingOrigin = "unknown";
                    } else if (request.resolveBindings) {
                        dto.resolutionStatus = "resolved";
                        ITypeBinding declaring = variable.getDeclaringClass();
                        dto.declaringType = declaring == null ? null : declaring.getQualifiedName();
                        dto.fieldBindingKey = variable.getKey();
                        dto.bindingOrigin = variableBindingOrigin(variable);
                    } else {
                        dto.resolutionStatus = "not_attempted";
                    }
                    fieldUses.add(dto);
                } else if (!request.resolveBindings && visibleFieldNames(owner.sourceKey).contains(node.getIdentifier())) {
                    FieldUseDto dto = new FieldUseDto();
                    dto.name = node.getIdentifier();
                    dto.range = range(node);
                    dto.resolutionStatus = "not_attempted";
                    fieldUses.add(dto);
                }
                return true;
            }

            private InvocationDto invocationBase(String kind, String name, ASTNode node, List<?> args) {
                InvocationDto dto = new InvocationDto();
                dto.sourceKey = method.sourceKey + "#" + ("constructor".equals(kind) ? "new" : "call") + ":" + byteSpan(node);
                dto.kind = kind;
                dto.name = name;
                dto.argumentCount = args.size();
                dto.arguments = new ArrayList<>();
                for (Object arg : args) {
                    if (arg instanceof ASTNode argNode) {
                        ArgumentDto argument = new ArgumentDto();
                        argument.source = sourceSlice(argNode);
                        argument.range = range(argNode);
                        dto.arguments.add(argument);
                    }
                }
                dto.invocationRange = range(node);
                dto.resolutionStatus = request.resolveBindings ? "unresolved" : "not_attempted";
                return dto;
            }
        }

        private List<String> chainMembers(MethodInvocation node) {
            ArrayDeque<String> names = new ArrayDeque<>();
            ASTNode current = node;
            while (current instanceof MethodInvocation mi) {
                names.addFirst(mi.getName().getIdentifier());
                current = mi.getExpression();
            }
            return new ArrayList<>(names);
        }

        private Set<String> visibleFieldNames(String ownerSourceKey) {
            Set<String> names = new HashSet<>();
            String current = ownerSourceKey;
            while (current != null) {
                names.addAll(fieldNamesByType.getOrDefault(current, Set.of()));
                current = parentTypeByType.get(current);
            }
            return names;
        }

        private boolean isDeclarationName(SimpleName node) {
            ASTNode parent = node.getParent();
            if (parent instanceof VariableDeclarationFragment frag && frag.getName() == node) return true;
            if (parent instanceof SingleVariableDeclaration decl && decl.getName() == node) return true;
            if (parent instanceof MethodDeclaration method && method.getName() == node) return true;
            if (parent instanceof AbstractTypeDeclaration type && type.getName() == node) return true;
            return false;
        }

        private InvocationDto applyInvocationBinding(InvocationDto dto, IMethodBinding binding) {
            if (!request.resolveBindings) {
                dto.resolutionStatus = "not_attempted";
                return dto;
            }
            if (binding == null || binding.isRecovered()) {
                dto.resolutionStatus = "unresolved";
                dto.unresolvedReason = binding == null ? "missing method binding" : "recovered method binding";
                dto.bindingOrigin = "unknown";
                addSymbolDiagnostic(dto.name, dto.invocationRange, dto.unresolvedReason);
                return dto;
            }
            ITypeBinding declaring = binding.getDeclaringClass();
            dto.resolutionStatus = "resolved";
            dto.resolvedOwner = declaring == null ? null : declaring.getQualifiedName();
            dto.resolvedName = binding.isConstructor() ? (declaring == null ? dto.name : declaring.getName()) : binding.getName();
            dto.resolvedParameterTypes = new ArrayList<>();
            for (ITypeBinding parameter : binding.getParameterTypes()) dto.resolvedParameterTypes.add(typeRef(parameter));
            dto.resolvedBindingKey = binding.getKey();
            dto.resolvedDescriptor = methodDescriptor(binding);
            dto.resolvedReturnType = binding.isConstructor() ? null : typeRef(binding.getReturnType());
            dto.bindingOrigin = bindingOrigin(binding);
            return dto;
        }

        private void applyMethodBinding(MethodDeclarationDto dto, IMethodBinding binding) {
            if (!request.resolveBindings) {
                dto.resolutionStatus = "not_attempted";
                return;
            }
            if (binding == null || binding.isRecovered()) {
                dto.resolutionStatus = "unresolved";
                dto.unresolvedReason = binding == null ? "missing method binding" : "recovered method binding";
                dto.bindingOrigin = "unknown";
                addSymbolDiagnostic(dto.name, dto.declarationRange, dto.unresolvedReason);
                return;
            }
            dto.resolutionStatus = "resolved";
            dto.resolvedBindingKey = binding.getKey();
            dto.resolvedDescriptor = methodDescriptor(binding);
            dto.bindingOrigin = bindingOrigin(binding);
        }

        private void applyVariableBinding(FieldDeclarationDto dto, IVariableBinding binding) {
            if (!request.resolveBindings) {
                dto.resolutionStatus = "not_attempted";
                return;
            }
            if (binding == null || binding.isRecovered()) {
                dto.resolutionStatus = "unresolved";
                dto.unresolvedReason = binding == null ? "missing field binding" : "recovered field binding";
                dto.bindingOrigin = "unknown";
                addSymbolDiagnostic(dto.name, dto.declarationRange, dto.unresolvedReason);
                return;
            }
            dto.resolutionStatus = "resolved";
            dto.bindingKey = binding.getKey();
            dto.bindingOrigin = variableBindingOrigin(binding);
        }

        private void applyTypeBinding(TypeDeclarationDto dto, BindingFacts binding) {
            dto.resolutionStatus = binding.status;
            dto.unresolvedReason = binding.unresolvedReason;
            dto.bindingKey = binding.key;
            dto.bindingOrigin = binding.origin;
        }

        private BindingFacts typeBindingFacts(ITypeBinding binding) {
            if (!request.resolveBindings) return BindingFacts.notAttempted();
            if (binding == null || binding.isRecovered()) {
                BindingFacts facts = BindingFacts.unresolved(binding == null ? "missing type binding" : "recovered type binding");
                return facts;
            }
            BindingFacts facts = new BindingFacts();
            facts.status = "resolved";
            facts.key = binding.getKey();
            facts.origin = bindingOrigin(binding);
            return facts;
        }

        private TypeRefDto typeRef(Type type) {
            if (type == null) return null;
            ITypeBinding binding = type.resolveBinding();
            TypeRefDto dto = binding == null || binding.isRecovered() ? new TypeRefDto() : typeRef(binding);
            dto.source = type.toString();
            dto.arrayDimensions = countArrayDimensions(type.toString());
            dto.varargs = false;
            if (binding == null || binding.isRecovered()) {
                dto.resolutionStatus = request.resolveBindings ? "unresolved" : "not_attempted";
                dto.unresolvedReason = request.resolveBindings ? (binding == null ? "missing type binding" : "recovered type binding") : null;
                dto.bindingOrigin = request.resolveBindings ? "unknown" : null;
            }
            return dto;
        }

        private TypeRefDto typeRef(ITypeBinding binding) {
            TypeRefDto dto = new TypeRefDto();
            dto.source = binding.getName();
            dto.qualifiedName = binding.getQualifiedName().isEmpty() ? null : binding.getQualifiedName();
            dto.binaryName = binding.getBinaryName();
            dto.descriptor = descriptor(binding);
            dto.arrayDimensions = binding.getDimensions();
            dto.varargs = false;
            dto.typeArguments = new ArrayList<>();
            for (ITypeBinding argument : binding.getTypeArguments()) dto.typeArguments.add(typeRef(argument));
            dto.resolutionStatus = binding.isRecovered() ? "unresolved" : "resolved";
            dto.unresolvedReason = binding.isRecovered() ? "recovered type binding" : null;
            dto.bindingKey = binding.isRecovered() ? null : binding.getKey();
            dto.bindingOrigin = binding.isRecovered() ? "unknown" : bindingOrigin(binding);
            return dto;
        }

        private List<TypeRefDto> typeRefs(List<?> rawTypes) {
            List<TypeRefDto> result = new ArrayList<>();
            for (Object raw : rawTypes) if (raw instanceof Type type) result.add(typeRef(type));
            return result;
        }

        private List<ParameterDto> parameters(List<?> raw) {
            List<ParameterDto> result = new ArrayList<>();
            for (Object item : raw) {
                SingleVariableDeclaration decl = (SingleVariableDeclaration) item;
                ParameterDto dto = new ParameterDto();
                dto.name = decl.getName().getIdentifier();
                dto.type = typeRef(decl.getType());
                if (dto.type != null) {
                    dto.type.varargs = decl.isVarargs();
                    if (decl.isVarargs()) dto.type.arrayDimensions = Math.max(1, dto.type.arrayDimensions == null ? 1 : dto.type.arrayDimensions);
                }
                dto.range = range(decl);
                result.add(dto);
            }
            return result;
        }

        private List<String> syntacticParameterTypes(List<ParameterDto> parameters) {
            List<String> result = new ArrayList<>();
            for (ParameterDto param : parameters) result.add(qualifiedSyntactic(param.type, Boolean.TRUE.equals(param.type == null ? false : param.type.varargs)));
            return result;
        }

        private String qualifiedSyntactic(TypeRefDto type, boolean varargs) {
            if (type == null || type.source == null) return "";
            if ("resolved".equals(type.resolutionStatus)) {
                String qualified = type.qualifiedName;
                if (qualified == null || qualified.isBlank()) qualified = type.source;
                if (varargs && !qualified.endsWith("[]")) qualified += "[]";
                return qualified;
            }
            String sourceText = type.source.replace("...", "[]");
            if (varargs && !sourceText.endsWith("[]")) sourceText += "[]";
            return qualifyTypeExpression(sourceText);
        }

        private String qualifyTypeExpression(String text) {
            String result = text;
            result = result.replaceAll("\\bString\\b", "java.lang.String");
            result = result.replaceAll("\\bInteger\\b", "java.lang.Integer");
            result = result.replaceAll("\\bLong\\b", "java.lang.Long");
            result = result.replaceAll("\\bBoolean\\b", "java.lang.Boolean");
            result = result.replaceAll("\\bDouble\\b", "java.lang.Double");
            result = result.replaceAll("\\bFloat\\b", "java.lang.Float");
            result = result.replaceAll("\\bObject\\b", "java.lang.Object");
            for (Map.Entry<String, String> entry : explicitImports.entrySet()) {
                result = result.replaceAll("\\b" + java.util.regex.Pattern.quote(entry.getKey()) + "\\b", entry.getValue());
            }
            return result;
        }

        private void fillSignatures(MethodDeclarationDto dto, TypeDeclarationDto owner) {
            String ownerName = owner.qualifiedName == null ? owner.name : owner.qualifiedName;
            String params = String.join(", ", dto.syntacticParameterTypes == null ? List.of() : dto.syntacticParameterTypes);
            dto.displaySignature = ownerName + "." + dto.name + "(" + params + ")";
            dto.fullSignature = dto.displaySignature;
            dto.sourceKey = owner.sourceKey + "#method:" + ("constructor".equals(dto.kind) || "compact_constructor".equals(dto.kind) ? "<init>" : dto.name) + "/" + (dto.syntacticParameterTypes == null ? 0 : dto.syntacticParameterTypes.size()) + "/" + String.join(",", dto.syntacticParameterTypes == null ? List.of() : dto.syntacticParameterTypes) + "#range:" + byteSpan(dto.declarationRange);
        }

        private TypeFrame typeFrame(AbstractTypeDeclaration node, TypeFrame parent, ClassInstanceCreation creation) {
            String pkg = cu.getPackage() == null ? null : cu.getPackage().getName().getFullyQualifiedName();
            String simple;
            boolean local = false;
            if (node == null) {
                simple = "<anonymous" + anonymousOrdinal++ + ">";
            } else {
                simple = node.getName().getIdentifier();
                local = parent != null && isInsideMethod(node);
            }
            String qualified;
            if (parent == null) qualified = pkg == null || pkg.isBlank() ? simple : pkg + "." + simple;
            else qualified = parent.qualifiedName + "." + simple;
            TypeFrame frame = new TypeFrame();
            frame.name = simple;
            frame.qualifiedName = qualified;
            List<String> nesting = new ArrayList<>();
            if (parent != null) nesting.addAll(parent.nestingPath);
            nesting.add(qualified);
            frame.nestingPath = nesting;
            int start = node == null ? creation.getStartPosition() : node.getStartPosition();
            int length = node == null ? creation.getLength() : node.getLength();
            String role = node == null ? "anonymous" : (local ? "local" : "type");
            int ordinal = local ? localOrdinal++ : -1;
            if (node == null) ordinal = anonymousOrdinal - 1;
            frame.sourceKey = "file:" + request.relativePath + "#" + role + ":" + qualified + (ordinal >= 0 ? ":" + ordinal : "") + "#range:" + byteSpan(start, length);
            frame.localOrdinal = ordinal >= 0 ? ordinal : null;
            return frame;
        }

        private boolean isInsideMethod(ASTNode node) {
            ASTNode current = node.getParent();
            while (current != null) {
                if (current instanceof MethodDeclaration) return true;
                if (current instanceof AbstractTypeDeclaration || current instanceof AnonymousClassDeclaration) return false;
                current = current.getParent();
            }
            return false;
        }

        private String typeKind(AbstractTypeDeclaration node) {
            if (isInsideMethod(node)) return "local";
            if (node instanceof AnnotationTypeDeclaration) return "annotation";
            if (node instanceof EnumDeclaration) return "enum";
            if (node instanceof RecordDeclaration) return "record";
            if (node instanceof TypeDeclaration td && td.isInterface()) return "interface";
            return "class";
        }

        private ITypeBinding resolveTypeBinding(AbstractTypeDeclaration node) {
            if (node instanceof TypeDeclaration td) return td.resolveBinding();
            if (node instanceof EnumDeclaration ed) return ed.resolveBinding();
            if (node instanceof AnnotationTypeDeclaration ad) return ad.resolveBinding();
            if (node instanceof RecordDeclaration rd) return rd.resolveBinding();
            return null;
        }

        private List<?> bodyDeclarations(AbstractTypeDeclaration node) {
            if (node instanceof TypeDeclaration td) return td.bodyDeclarations();
            if (node instanceof EnumDeclaration ed) return ed.bodyDeclarations();
            if (node instanceof AnnotationTypeDeclaration ad) return ad.bodyDeclarations();
            if (node instanceof RecordDeclaration rd) return rd.bodyDeclarations();
            return List.of();
        }

        private List<String> bodyKinds(List<?> declarations) {
            List<String> result = new ArrayList<>();
            for (Object child : declarations) {
                if (child instanceof FieldDeclaration) result.add("field");
                else if (child instanceof Initializer) result.add("initializer");
                else if (child instanceof MethodDeclaration method) result.add(method.isConstructor() ? "constructor" : "method");
                else if (child instanceof AbstractTypeDeclaration) result.add("type");
                else if ("AnnotationTypeMemberDeclaration".equals(child.getClass().getSimpleName())) result.add("annotation_member");
                else result.add(child.getClass().getSimpleName().toLowerCase(Locale.ROOT));
            }
            return result;
        }

        private List<String> typeBodyKinds(AbstractTypeDeclaration node) {
            List<String> result = new ArrayList<>(bodyKinds(bodyDeclarations(node)));
            if (node instanceof RecordDeclaration rd && !rd.recordComponents().isEmpty() && !result.contains("field")) {
                result.add("field");
            }
            if (request.resolveBindings && !hasExplicitConstructor(node)) {
                ITypeBinding binding = resolveTypeBinding(node);
                if (binding != null && !binding.isRecovered()) {
                    for (IMethodBinding method : binding.getDeclaredMethods()) {
                        if (method.isConstructor() && (method.isDefaultConstructor() || method.isCanonicalConstructor())) {
                            if (!result.contains("constructor")) result.add("constructor");
                            break;
                        }
                    }
                }
            }
            return result;
        }

        private List<String> modifiers(List<?> modifiers) {
            List<String> result = new ArrayList<>();
            for (Object modifier : modifiers) if (modifier instanceof Modifier m) result.add(m.getKeyword().toString());
            return result;
        }

        private List<String> annotations(List<?> modifiers) {
            List<String> result = new ArrayList<>();
            for (Object modifier : modifiers) if (modifier instanceof Annotation a) result.add(a.getTypeName().getFullyQualifiedName());
            return result;
        }

        private void addSymbolDiagnostic(String symbol, SourceRangeDto range, String reason) {
            DiagnosticDto dto = new DiagnosticDto();
            dto.severity = "warning";
            dto.phase = "symbol";
            dto.code = "symbol.unresolved";
            dto.message = symbol + ": " + reason;
            dto.range = range;
            dto.coverageImpact = "file_partial";
            diagnostics.add(dto);
        }

        private void addRecoveredDiagnosticIfNeeded(ASTNode node) {
            if ((node.getFlags() & ASTNode.RECOVERED) != 0 || (node.getFlags() & ASTNode.MALFORMED) != 0) {
                DiagnosticDto dto = new DiagnosticDto();
                dto.severity = "warning";
                dto.phase = "parse";
                dto.code = "jdt.recovered-node";
                dto.message = "recovered or malformed AST node omitted from authoritative facts";
                dto.range = range(node);
                dto.coverageImpact = "file_partial";
                diagnostics.add(dto);
            }
        }

        private String coverage() {
            boolean failed = diagnostics.stream().anyMatch(d -> "file_failed".equals(d.coverageImpact));
            if (failed) return "failed";
            boolean partial = diagnostics.stream().anyMatch(d -> d.coverageImpact != null && !d.coverageImpact.isBlank());
            return partial ? "partial" : "complete";
        }

        private SourceRangeDto range(ASTNode node) {
            return range(node.getStartPosition(), node.getLength(), "JDT node source position unavailable");
        }

        private SourceRangeDto range(int start, int length, String reason) {
            SourceRangeDto dto = new SourceRangeDto();
            if (start < 0 || length < 0 || start + length > chars.length || !utf8Index.hasBoundary(start) || !utf8Index.hasBoundary(start + length)) {
                dto.status = "unverified";
                dto.reason = reason;
                return dto;
            }

            dto.status = "verified";
            dto.startUtf16Offset = start;
            dto.endUtf16Offset = start + length;
            dto.startByte = utf8Index.byteOffset(start);
            dto.endByte = utf8Index.byteOffset(start + length);
            dto.startLine = Math.max(1, cu.getLineNumber(start));
            int endChar = length == 0 ? start : start + length - 1;
            dto.endLine = Math.max(dto.startLine, cu.getLineNumber(endChar));
            return dto;
        }

        private SourceRangeDto absentRange(String reason) {
            SourceRangeDto dto = new SourceRangeDto();
            dto.status = "absent";
            dto.reason = reason;
            return dto;
        }

        private String sourceSlice(ASTNode node) {
            int start = node.getStartPosition();
            int end = start + node.getLength();
            if (start < 0 || end > source.length() || start > end) return "";
            return source.substring(start, end);
        }

        private String byteSpan(ASTNode node) {
            return byteSpan(node.getStartPosition(), node.getLength());
        }

        private String byteSpan(SourceRangeDto range) {
            return range.startByte + "-" + range.endByte;
        }

        private String byteSpan(int start, int length) {
            SourceRangeDto r = range(start, length, "source position unavailable");
            return r.startByte + "-" + r.endByte;
        }

        private void sortByRange(List<? extends HasRange> items) {
            items.sort(Comparator.comparingInt(item -> item.rangeStart() == null ? Integer.MAX_VALUE : item.rangeStart()));
        }
    }

    private static String bindingOrigin(IBinding binding) {
        if (binding instanceof ITypeBinding type) return bindingOrigin(type);
        if (binding instanceof IMethodBinding method) {
            ITypeBinding declaring = method.getDeclaringClass();
            if (declaring != null && !declaring.isRecovered()) return bindingOrigin(declaring);
            return "binary";
        }
        if (binding instanceof IVariableBinding variable) return variableBindingOrigin(variable);
        return "unknown";
    }

    private static String variableBindingOrigin(IVariableBinding variable) {
        ITypeBinding declaring = variable == null ? null : variable.getDeclaringClass();
        if (declaring != null && !declaring.isRecovered()) return bindingOrigin(declaring);
        return variable != null && variable.isField() ? "binary" : "unknown";
    }

    private static String bindingOrigin(ITypeBinding type) {
        if (type == null || type.isRecovered()) return "unknown";
        if (type.isPrimitive()) return "primitive";
        if (type.isArray()) return bindingOrigin(type.getElementType());
        return type.isFromSource() ? "source" : "binary";
    }

    private static String descriptor(ITypeBinding type) {
        if (type == null || type.isRecovered()) return null;
        ITypeBinding erased = type.getErasure();
        if (erased != null && !erased.isRecovered() && erased != type) return descriptor(erased);
        if (type.isArray()) {
            String elementDescriptor = descriptor(type.getElementType());
            return elementDescriptor == null ? null : "[".repeat(type.getDimensions()) + elementDescriptor;
        }
        if (type.isPrimitive()) {
            return switch (type.getName()) {
                case "void" -> "V";
                case "boolean" -> "Z";
                case "byte" -> "B";
                case "char" -> "C";
                case "short" -> "S";
                case "int" -> "I";
                case "long" -> "J";
                case "float" -> "F";
                case "double" -> "D";
                default -> null;
            };
        }
        String binary = type.getBinaryName();
        if (binary == null || binary.isBlank()) binary = type.getQualifiedName();
        if (binary == null || binary.isBlank()) return null;
        return "L" + binary.replace('.', '/') + ";";
    }

    private static String methodDescriptor(IMethodBinding binding) {
        if (binding == null || binding.isRecovered()) return null;
        StringBuilder sb = new StringBuilder("(");
        for (ITypeBinding parameter : binding.getParameterTypes()) {
            String parameterDescriptor = descriptor(parameter);
            if (parameterDescriptor == null) return null;
            sb.append(parameterDescriptor);
        }
        sb.append(')');
        String returnDescriptor = binding.isConstructor() ? "V" : descriptor(binding.getReturnType());
        if (returnDescriptor == null) return null;
        sb.append(returnDescriptor);
        return sb.toString();
    }

    private static int countArrayDimensions(String source) {
        int count = 0;
        int idx = source.indexOf("[]");
        while (idx >= 0) {
            count++;
            idx = source.indexOf("[]", idx + 2);
        }
        return count;
    }

    private static String simpleName(String qualified) {
        int dot = qualified.lastIndexOf('.');
        return dot >= 0 ? qualified.substring(dot + 1) : qualified;
    }

    private static boolean isSupportedLanguageLevel(String level) {
        if (level == null || level.isBlank()) return false;
        try {
            int release = Integer.parseInt(level);
            return release >= 8 && release <= 25;
        } catch (NumberFormatException ex) {
            return false;
        }
    }

    private static void updateFileDigest(MessageDigest digest, Path path) throws IOException {
        try (InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
    }

    private static void updateFingerprintEntry(MessageDigest digest, String kind, String entry) throws IOException {
        Path path = Paths.get(entry);
        updateDigest(digest, kind);
        updateDigest(digest, "\n");
        updateDigest(digest, path.toString());
        updateDigest(digest, "\n");
        if (Files.isRegularFile(path)) {
            updateDigest(digest, "file\n");
            updateFileDigest(digest, path);
            updateDigest(digest, "\n");
            return;
        }
        if (!Files.isDirectory(path)) {
            throw new IOException("Analysis path is unavailable: " + path);
        }
        updateDigest(digest, "directory\n");
        try (Stream<Path> stream = Files.walk(path)) {
            List<Path> files = stream
                    .filter(p -> p.toString().endsWith(kind.equals("source_root") ? ".java" : ".class"))
                    .filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(p -> path.relativize(p).toString()))
                    .toList();
            for (Path file : files) {
                updateDigest(digest, path.relativize(file).toString());
                updateDigest(digest, "\n");
                updateFileDigest(digest, file);
                updateDigest(digest, "\n");
            }
        }
    }

    private static void updateDigest(MessageDigest digest, String value) {
        digest.update(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return hex(digest.digest(bytes));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static final class Utf8Index {
        private final int[] byteOffsets;
        private final boolean[] boundaries;

        Utf8Index(String source) {
            byteOffsets = new int[source.length() + 1];
            boundaries = new boolean[source.length() + 1];
            int bytes = 0;
            for (int i = 0; i < source.length();) {
                int codePoint = source.codePointAt(i);
                int chars = Character.charCount(codePoint);
                boundaries[i] = true;
                byteOffsets[i] = bytes;
                byte[] encoded = new String(Character.toChars(codePoint)).getBytes(StandardCharsets.UTF_8);
                for (int j = 1; j < chars; j++) {
                    byteOffsets[i + j] = bytes;
                    boundaries[i + j] = false;
                }
                bytes += encoded.length;
                i += chars;
            }
            boundaries[source.length()] = true;
            byteOffsets[source.length()] = bytes;
        }

        boolean hasBoundary(int utf16Offset) {
            return utf16Offset >= 0 && utf16Offset < boundaries.length && boundaries[utf16Offset];
        }

        int byteOffset(int utf16Offset) {
            return byteOffsets[utf16Offset];
        }
    }

    private static final class Request {
        String schemaVersion;
        String relativePath;
        String sourceBase64;
        String languageLevel;
        boolean resolveBindings;
        List<String> classpath;
        List<String> sourceRoots;
        transient byte[] sourceBytes;
    }

    private static final class FatalProtocolException extends RuntimeException {
        FatalProtocolException(String message) { super(message); }
    }

    private interface HasRange {
        Integer rangeStart();
    }

    private static final class TypeFrame {
        String name;
        String qualifiedName;
        String sourceKey;
        List<String> nestingPath;
        Integer localOrdinal;
    }

    private static final class BindingFacts {
        String status;
        String unresolvedReason;
        String key;
        String origin;
        static BindingFacts notAttempted() { BindingFacts f = new BindingFacts(); f.status = "not_attempted"; return f; }
        static BindingFacts unresolved(String reason) { BindingFacts f = new BindingFacts(); f.status = "unresolved"; f.unresolvedReason = reason; f.origin = "unknown"; return f; }
    }

    private static final class ParsedJavaFileDto {
        String schemaVersion;
        JavaParserProvenanceDto provenance;
        String relativePath;
        String packageName;
        List<ImportDto> imports = List.of();
        String sourceSha256;
        int sourceByteLength;
        String coverage;
        List<DiagnosticDto> diagnostics = List.of();
        List<TypeDeclarationDto> types = List.of();
        List<FieldDeclarationDto> fields = List.of();
        List<MethodDeclarationDto> methods = List.of();
    }

    private static final class JavaParserProvenanceDto {
        String backend;
        String backendVersion;
        String adapterVersion;
        String languageLevel;
        boolean resolutionEnabled;
        String classpathFingerprint;
    }

    private static final class SourceRangeDto {
        Integer startByte;
        Integer endByte;
        Integer startLine;
        Integer endLine;
        Integer startUtf16Offset;
        Integer endUtf16Offset;
        String status;
        String reason;
    }

    private static final class DiagnosticDto {
        String severity;
        String phase;
        String code;
        String message;
        SourceRangeDto range;
        String coverageImpact;
    }

    private static final class ImportDto {
        String name;
        boolean isStatic;
        boolean onDemand;
        SourceRangeDto range;
    }

    private static final class TypeRefDto {
        String source;
        String qualifiedName;
        String binaryName;
        String descriptor;
        Integer arrayDimensions;
        Boolean varargs;
        List<TypeRefDto> typeArguments = List.of();
        String resolutionStatus;
        String unresolvedReason;
        String bindingKey;
        String bindingOrigin;
    }

    private static final class TypeDeclarationDto implements HasRange {
        String sourceKey;
        String kind;
        String name;
        String qualifiedName;
        String binaryName;
        List<String> nestingPath = List.of();
        String enclosingTypeSourceKey;
        List<String> bodyDeclarationKinds = List.of();
        List<String> modifiers = List.of();
        List<String> annotationNames = List.of();
        TypeRefDto superclass;
        List<TypeRefDto> interfaces = List.of();
        SourceRangeDto declarationRange;
        SourceRangeDto nameRange;
        String resolutionStatus;
        String unresolvedReason;
        String bindingKey;
        String bindingOrigin;
        Integer localOrdinal;
        @Override public Integer rangeStart() { return declarationRange == null ? null : declarationRange.startByte; }
    }

    private static final class FieldDeclarationDto implements HasRange {
        String sourceKey;
        String declaringTypeSourceKey;
        String name;
        TypeRefDto type;
        List<String> modifiers = List.of();
        List<String> annotationNames = List.of();
        SourceRangeDto declarationRange;
        SourceRangeDto nameRange;
        SourceRangeDto initializerRange;
        boolean hasInitializer;
        String resolutionStatus;
        String unresolvedReason;
        String bindingKey;
        String bindingOrigin;
        @Override public Integer rangeStart() { return declarationRange == null ? null : declarationRange.startByte; }
    }

    private static final class ParameterDto {
        String name;
        TypeRefDto type;
        SourceRangeDto range;
    }

    private static final class MethodDeclarationDto implements HasRange {
        String sourceKey;
        String declarationKey;
        String declaringTypeSourceKey;
        String declaringTypeQualifiedName;
        String kind;
        String name;
        String displaySignature;
        String fullSignature;
        List<String> syntacticParameterTypes = List.of();
        List<String> modifiers = List.of();
        List<String> annotationNames = List.of();
        TypeRefDto returnType;
        List<ParameterDto> parameters = List.of();
        List<TypeRefDto> thrownTypes = List.of();
        SourceRangeDto declarationRange;
        SourceRangeDto nameRange;
        SourceRangeDto bodyRange;
        List<InvocationDto> invocations = List.of();
        List<FieldUseDto> fieldUses = List.of();
        String resolutionStatus;
        String unresolvedReason;
        String resolvedBindingKey;
        String resolvedDescriptor;
        String bindingOrigin;
        @Override public Integer rangeStart() { return declarationRange == null ? null : declarationRange.startByte; }
    }

    private static final class InvocationDto {
        String sourceKey;
        String kind;
        String qualifierSource;
        String name;
        int argumentCount;
        List<ArgumentDto> arguments = List.of();
        SourceRangeDto invocationRange;
        Boolean terminalChainMember;
        List<String> chainMembers = List.of();
        String resolutionStatus;
        String unresolvedReason;
        String resolvedOwner;
        String resolvedName;
        List<TypeRefDto> resolvedParameterTypes = List.of();
        TypeRefDto resolvedReturnType;
        String resolvedBindingKey;
        String resolvedDescriptor;
        String bindingOrigin;
    }

    private static final class ArgumentDto {
        String source;
        SourceRangeDto range;
    }

    private static final class FieldUseDto {
        String name;
        SourceRangeDto range;
        String resolutionStatus;
        String unresolvedReason;
        String declaringType;
        String fieldBindingKey;
        String bindingOrigin;
    }
}
