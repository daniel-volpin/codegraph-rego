package iso27001

# Evidence bundle schema (per Method):
# input = {
#   "target_method": "com.example.Controller.deleteUser",
#   "method_name": "deleteUser",
#   "graph_context": {
#       "annotations": ["GetMapping", "PreAuthorize"],
#       "uses_fields": [{"name": "auditLogger", "type": "Logger"}],
#       "calls": ["MessageDigest.getInstance(\"MD5\")"],
#       "callers": ["..."]
#   },
#   "source_code": "..."
# }

endpoint_annotations := {"requestmapping", "getmapping", "postmapping", "putmapping", "deletemapping", "patchmapping"}
security_annotations := {"preauthorize", "secured", "rolesallowed", "denyall", "authorize"}
sensitive_keywords := {"delete", "remove", "destroy", "update", "modify", "drop"}
logger_indicators := {"logger", "audit", "tracer"}
md5_pattern := "messagedigest.getinstance(\"md5\")"
des_pattern := "cipher.getinstance(\"des"
rc4_pattern := "cipher.getinstance(\"rc4"
ecb_pattern := "cipher.getinstance(\"aes/ecb"
random_ctor_pattern := "new random("
math_random_pattern := "math.random("
java_util_random_pattern := "java.util.random"
threadlocal_random_pattern := "threadlocalrandom.current"
sha1prng_pattern := "sha1prng"
sql_execute_pattern := "executequery("
sql_execute_update_pattern := "executeupdate("
sql_execute_generic_pattern := "execute("
sql_prepare_pattern := "preparestatement("
sql_keywords := {"select ", "insert ", "update ", "delete "}
untrusted_input_markers := {"getparameter(", "getheader(", "getquerystring(", "getcookies("}

normalized_annotations := {normalized |
  annotations := input.graph_context.annotations
  annotations != null
  ann := annotations[_]
  normalized := lower(replace(ann, "@", ""))
}

has_endpoint_annotation if {
  ann := normalized_annotations[_]
  ann in endpoint_annotations
}

has_security_annotation if {
  ann := normalized_annotations[_]
  ann in security_annotations
}

method_name := lower(input.method_name) if {
  input.method_name != null
}

method_name := lower(input.target_method) if {
  input.method_name == null
  input.target_method != null
}

sensitive_method if {
  method_name != ""
  kw := sensitive_keywords[_]
  contains(method_name, kw)
}

uses_logger_field if {
  fields := input.graph_context.uses_fields
  fields != null
  field := fields[_]
  field.type != null
  type := lower(field.type)
  indicator := logger_indicators[_]
  contains(type, indicator)
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

servlet_context if {
  has_endpoint_annotation
}

servlet_context if {
  input.target_method != null
  contains(lower(input.target_method), "httpservletrequest")
}

servlet_context if {
  input.source_code != null
  contains(lower(input.source_code), "httpservletrequest")
}

benchmark_context if {
  input.target_method != null
  contains(lower(input.target_method), "benchmarktest")
}

random_context if {
  servlet_context
}

random_context if {
  benchmark_context
}

source_insecure_random if {
  input.source_code != null
  src := lower(input.source_code)
  contains(src, random_ctor_pattern)
}

source_insecure_random if {
  input.source_code != null
  src := lower(input.source_code)
  contains(src, math_random_pattern)
}

source_insecure_random if {
  input.source_code != null
  src := lower(input.source_code)
  contains(src, java_util_random_pattern)
}

source_insecure_random if {
  input.source_code != null
  src := lower(input.source_code)
  contains(src, threadlocal_random_pattern)
}

source_insecure_random if {
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

sql_source_exec if {
  input.source_code != null
  src := lower(input.source_code)
  contains(src, sql_execute_pattern)
}

sql_source_exec if {
  input.source_code != null
  src := lower(input.source_code)
  contains(src, sql_execute_update_pattern)
}

sql_source_exec if {
  input.source_code != null
  src := lower(input.source_code)
  contains(src, sql_execute_generic_pattern)
}

sql_source_prepare if {
  input.source_code != null
  src := lower(input.source_code)
  contains(src, sql_prepare_pattern)
}

sql_calls if {
  calls := input.graph_context.calls
  calls != null
  call := calls[_]
  call != null
  contains(lower(call), "java.sql.")
}

sql_present if {
  sql_source_exec
}

sql_present if {
  sql_source_prepare
}

sql_present if {
  sql_calls
}

sql_injection_heuristic if {
  servlet_context
  input.source_code != null
  sql_present
  src := lower(input.source_code)
  contains(src, "+")
  some kw in sql_keywords
  contains(src, kw)
  some marker in untrusted_input_markers
  contains(src, marker)
}

violations[v] if {
  has_endpoint_annotation
  not has_security_annotation
  v := violation_record("ISO-A.9.4.1", "Public HTTP endpoint missing security annotations")
}

violations[v] if {
  sensitive_method
  not uses_logger_field
  v := violation_record("ISO-A.12.4.1", "Sensitive mutation lacks logger usage")
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

violations[v] if {
  sql_injection_heuristic
  v := violation_record("ISO-A.8-SQL-INJECTION", "Possible SQL injection via string concatenation")
}

violation_record(id, reason) := {
  "violation_id": id,
  "target_method": input.target_method,
  "reason": reason,
  "severity": "high",
}
