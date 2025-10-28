package iso27001

# ISO 27001 A.9.1.1 - Access control policy
# This policy flags public HTTP endpoint methods that lack any security annotation.
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
security_annotations := {"PreAuthorize", "Secured", "RolesAllowed", "PermitAll", "DenyAll"}

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

# A.9.1.1 - Public endpoints should enforce access control
# Produce an array of violation objects
violations := [v | 
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
