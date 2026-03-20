package iso27001

md5_pattern := "messagedigest.getinstance(\"md5\""
sha1_pattern := "messagedigest.getinstance(\"sha1\""
sha_dash_pattern := "messagedigest.getinstance(\"sha-1\""
des_pattern := "cipher.getinstance(\"des"
rc4_pattern := "cipher.getinstance(\"rc4"
ecb_pattern := "cipher.getinstance(\"aes/ecb"
random_ctor_pattern := "new random("
math_random_pattern := "math.random("
threadlocal_random_pattern := "threadlocalrandom.current("

weak_hash_patterns := {md5_pattern, sha1_pattern, sha_dash_pattern}
weak_cipher_patterns := {des_pattern, rc4_pattern, ecb_pattern}
insecure_random_patterns := {random_ctor_pattern, math_random_pattern, threadlocal_random_pattern}

random_context if {
	servlet_context
}

random_context if {
	benchmark_context
}

source_contains(pattern) if {
	input.source_code != null
	contains(lower(input.source_code), pattern)
}

source_contains_any(patterns) if {
	some pattern in patterns
	source_contains(pattern)
}

graph_calls_contain(pattern) if {
	calls := input.graph_context.calls
	calls != null
	call := calls[_]
	call != null
	contains(lower(call), pattern)
}

graph_calls_contain_any(patterns) if {
	some pattern in patterns
	graph_calls_contain(pattern)
}

flag_enabled(name) if {
	flags := object.get(input, "analysis_flags", {})
	object.get(flags, name, false) == true
}

calls_md5 if {
	graph_calls_contain(md5_pattern)
}

calls_weak_hash if {
	graph_calls_contain_any(weak_hash_patterns)
}

source_md5 if {
	source_contains(md5_pattern)
}

source_weak_hash if {
	source_contains_any(weak_hash_patterns)
}

analysis_md5 if {
	flag_enabled("md5_detected")
}

analysis_weak_hash if {
	flag_enabled("weak_hash_detected")
}

analysis_weak_cipher if {
	flag_enabled("weak_cipher_detected")
}

source_weak_cipher if {
	source_contains_any(weak_cipher_patterns)
}

source_insecure_random if {
	input.analysis_flags == null
	source_contains_any(insecure_random_patterns)
}

analysis_insecure_random if {
	flag_enabled("insecure_random_detected")
}

calls_insecure_random if {
	graph_calls_contain("java.util.random")
}

insecure_random if {
	random_context
	source_insecure_random
}

insecure_random if {
	random_context
	calls_insecure_random
}

insecure_random if {
	random_context
	analysis_insecure_random
}

weak_hash_detected if {
	calls_md5
}

weak_hash_detected if {
	source_md5
}

weak_hash_detected if {
	analysis_md5
}

weak_hash_detected if {
	analysis_weak_hash
}

weak_hash_detected if {
	calls_weak_hash
}

weak_hash_detected if {
	source_weak_hash
}

weak_cipher_detected if {
	analysis_weak_cipher
}

weak_cipher_detected if {
	source_weak_cipher
}

violations[v] if {
	weak_hash_detected
	v := violation_record("ISO-A.10-WEAK-HASH", "Weak hash usage detected")
}

violations[v] if {
	weak_cipher_detected
	v := violation_record("ISO-A.10-WEAK-CRYPTO", "Weak cipher usage detected")
}

violations[v] if {
	insecure_random
	v := violation_record("ISO-A.10-WEAK-RANDOM", "Insecure randomness usage detected")
}
