package iso27001

# ISO 27001 controls enforced:
#   - A.9.1.1 Access control policy (public endpoints missing security annotations)
#   - A.9.4.2 Secure log-on procedures (authentication endpoints lack protection)
#   - A.12.4.1 Event logging (critical operations without evidence of logging)
#
# Expected input shape (from policy_integration.py):
# {
#   "methods": [
#     {
#       "signature": "com.example.Controller.getUsers()",
#       "name": "getUsers",
#       "annotations": ["GetMapping", "PreAuthorize"],
#       "modifiers": ["public"],
#       "file_path": "/path/to/Controller.java"
#     }, ...
#   ]
# }

endpoint_annotations := {"RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping"}
mutation_annotations := {"PostMapping", "PutMapping", "DeleteMapping", "PatchMapping"}
security_annotations := {"PreAuthorize", "Secured", "RolesAllowed", "DenyAll"}
authentication_keywords := {"login", "signin", "authenticate", "auth", "resetpassword", "forgotpassword"}
logging_annotations := {"Audit", "Audited", "Loggable", "AuditLog", "Traceable"}
logging_call_keywords := {".info()", ".warn()", ".error()", ".debug()", ".trace()", "logger.", "log.", "audit"}
critical_operation_keywords := {"create", "update", "delete", "remove", "submit", "register", "approve", "transfer"}

public(m) if {
  m.modifiers[_] == "public"
}

is_endpoint(m) if {
  ann := m.annotations[_]
  ann in endpoint_annotations
}

is_secured(m) if {
  ann := m.annotations[_]
  ann in security_annotations
}

is_authentication_endpoint(m) if {
  is_endpoint(m)
  m.name != null
  lower_name := lower(m.name)
  kw := authentication_keywords[_]
  contains(lower_name, kw)
}

is_mutation_endpoint(m) if {
  ann := m.annotations[_]
  ann in mutation_annotations
}

requires_logging(m) if {
  is_endpoint(m)
  public(m)
  is_mutation_endpoint(m)
}

requires_logging(m) if {
  is_endpoint(m)
  public(m)
  method_name_matches_keyword(m)
}

method_name_matches_keyword(m) if {
  name := m.name
  name != null
  kw := critical_operation_keywords[_]
  contains(lower(name), kw)
}

has_logging_annotation(m) if {
  ann := m.annotations[_]
  ann in logging_annotations
}

has_logging_call(m) if {
  cs := m.called_signatures
  sig := cs[_]
  call_has_logging(sig)
}

call_has_logging(sig) if {
  sig != null
  k := logging_call_keywords[_]
  contains(lower(sig), lower(k))
}

has_logging_control(m) if {
  has_logging_annotation(m)
}

has_logging_control(m) if {
  has_logging_call(m)
}

# Individual control helpers that emit violation arrays
access_control_violations := [v |
  m := input.methods[_];
  is_endpoint(m);
  public(m);
  not is_secured(m);
  v := {
    "standard": "ISO-27001",
    "id": "A.9.1.1",
    "method": m.signature,
    "file_path": m.file_path,
    "reason": "Public HTTP endpoint missing security annotation"
  }
]

secure_logon_violations := [v |
  m := input.methods[_];
  is_authentication_endpoint(m);
  public(m);
  not is_secured(m);
  v := {
    "standard": "ISO-27001",
    "id": "A.9.4.2",
    "method": m.signature,
    "file_path": m.file_path,
    "reason": "Authentication endpoint lacks enforced authentication control"
  }
]

logging_control_violations := [v |
  m := input.methods[_];
  requires_logging(m);
  not has_logging_control(m);
  v := {
    "standard": "ISO-27001",
    "id": "A.12.4.1",
    "method": m.signature,
    "file_path": m.file_path,
    "reason": "Critical operation endpoint has no evidence of security logging"
  }
]

violations := array.concat(access_control_violations, array.concat(secure_logon_violations, logging_control_violations))
