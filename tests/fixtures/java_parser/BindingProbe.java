package com.acme;

import java.util.List;

public class BindingProbe {
    public String probe(FixtureLib lib, MissingThing missing) {
        List<String> values = List.of("x");
        String here = helper();
        String binary = lib.ping();
        missing.absent();
        return values.get(0) + here + binary;
    }

    private String helper() { return "source"; }
}
