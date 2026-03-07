package iso27001

md5_pattern := "messagedigest.getinstance(\"md5\")"
des_pattern := "cipher.getinstance(\"des"
rc4_pattern := "cipher.getinstance(\"rc4"
ecb_pattern := "cipher.getinstance(\"aes/ecb"
random_ctor_pattern := "new random("
math_random_pattern := "math.random("
threadlocal_random_pattern := "threadlocalrandom.current("
sha1prng_pattern := "securerandom.getinstance(\"sha1prng\")"

random_context if {
  servlet_context
}

random_context if {
  benchmark_context
}

calls_md5 if {
  calls := input.graph_context.calls
  calls != null
  call := calls[_]
  call != null
  contains(lower(call), md5_pattern)
}

source_md5 if {
  input.source_code != null
  contains(lower(input.source_code), md5_pattern)
}

analysis_md5 if {
  flags := input.analysis_flags
  flags.md5_detected == true
}

analysis_weak_cipher if {
  flags := input.analysis_flags
  flags.weak_cipher_detected == true
}

source_weak_cipher if {
  input.source_code != null
  src := lower(input.source_code)
  contains(src, des_pattern)
}

source_weak_cipher if {
  input.source_code != null
  src := lower(input.source_code)
  contains(src, rc4_pattern)
}

source_weak_cipher if {
  input.source_code != null
  src := lower(input.source_code)
  contains(src, ecb_pattern)
}

source_insecure_random if {
  flags := input.analysis_flags
  flags == null
  input.source_code != null
  src := lower(input.source_code)
  contains(src, random_ctor_pattern)
}

source_insecure_random if {
  flags := input.analysis_flags
  flags == null
  input.source_code != null
  src := lower(input.source_code)
  contains(src, math_random_pattern)
}

source_insecure_random if {
  flags := input.analysis_flags
  flags == null
  input.source_code != null
  src := lower(input.source_code)
  contains(src, threadlocal_random_pattern)
}

source_insecure_random if {
  flags := input.analysis_flags
  flags == null
  input.source_code != null
  src := lower(input.source_code)
  contains(src, sha1prng_pattern)
}

analysis_insecure_random if {
  flags := input.analysis_flags
  flags.insecure_random_detected == true
}

calls_insecure_random if {
  calls := input.graph_context.calls
  calls != null
  call := calls[_]
  call != null
  contains(lower(call), "java.util.random")
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

violations[v] if {
  calls_md5
  v := violation_record("ISO-A.10-WEAK-HASH", "Insecure MD5 digest usage detected")
}

violations[v] if {
  source_md5
  v := violation_record("ISO-A.10-WEAK-HASH", "Insecure MD5 digest usage detected")
}

violations[v] if {
  analysis_md5
  v := violation_record("ISO-A.10-WEAK-HASH", "Insecure MD5 digest usage detected")
}

violations[v] if {
  analysis_weak_cipher
  v := violation_record("ISO-A.10-WEAK-CRYPTO", "Weak cipher usage detected")
}

violations[v] if {
  source_weak_cipher
  v := violation_record("ISO-A.10-WEAK-CRYPTO", "Weak cipher usage detected")
}

violations[v] if {
  insecure_random
  v := violation_record("ISO-A.10-WEAK-RANDOM", "Insecure randomness usage detected")
}
