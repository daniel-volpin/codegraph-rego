package io.github.codegraph.javaparser;

/** Single executable entrypoint for trusted JDT parse and source-edit operations. */
public final class AdapterMain {
    private static final String SOURCE_EDIT_COMMAND = "source-edit";

    private AdapterMain() {}

    public static void main(String[] args) {
        if (args.length == 0) {
            Main.main(args);
            return;
        }
        if (args.length == 1 && SOURCE_EDIT_COMMAND.equals(args[0])) {
            SourceEditor.run();
            return;
        }

        System.err.println("protocol fatal: expected no command or 'source-edit'");
        System.exit(2);
    }
}
