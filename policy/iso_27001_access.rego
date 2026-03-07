package iso27001

endpoint_annotations := {"requestmapping", "getmapping", "postmapping", "putmapping", "deletemapping", "patchmapping", "webservlet"}
security_annotations := {"preauthorize", "secured", "rolesallowed", "denyall", "authorize"}
sensitive_keywords := {"delete", "remove", "destroy", "update", "modify", "drop"}
logger_indicators := {"logger", "audit", "tracer"}
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

violation_record(id, reason) := {
  "violation_id": id,
  "target_method": input.target_method,
  "reason": reason,
  "severity": "high",
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
