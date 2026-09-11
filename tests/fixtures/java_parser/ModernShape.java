package com.acme;

import java.util.List;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Marker("demo")
public record ModernShape(String name, int count) implements Worker {
	private static final String TEXT = "line1\r\n🙂\\u0041";

	public ModernShape {
		if (count < 0) throw new IllegalArgumentException("count");
	}

	@Override
	public String run(List<String> values, int... numbers) throws Exception {
		String block = """
			alpha
			beta
			""";
		Object local = new Object() {
			String nested() { return block.strip(); }
		};
		class LocalThing {
			String call() { return TEXT.trim(); }
		}
		System.out.println(local.toString());
		return switch (values.size()) {
			case 0 -> new LocalThing().call();
			default -> name + numbers.length;
		};
	}

	static { System.getProperty("never.execute"); }
}

sealed interface Worker permits ModernShape {
	default String label() { return "worker"; }
	String run(List<String> values, int... numbers) throws Exception;
}

enum Mode { ON, OFF }

@Retention(RetentionPolicy.RUNTIME)
@interface Marker { String value(); }
