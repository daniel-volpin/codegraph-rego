package iso27001

sql_execute_pattern := "executequery("
sql_execute_update_pattern := "executeupdate("
sql_execute_generic_pattern := "execute("
sql_prepare_pattern := "preparestatement("
sql_prepare_call_pattern := "preparecall("
sql_callable_statement_pattern := "callablestatement"
sql_keywords := {"select ", "insert ", "update ", "delete "}

file_path_keywords := {"../", "..\\", "fileinputstream", "new java.io.file(", "paths.get(", "new java.io.filereader("}
command_keywords := {"processbuilder", ".command(", "runtime.getruntime().exec(", "cmd.exe", "sh", "/c", "-c"}
ldap_keywords := {"initialdircontext", "dircontext", ".search(", "uid=", "objectclass=person"}
xpath_keywords := {"xpathfactory.newinstance(", ".evaluate(", "/employees/employee["}

input_is_untrusted if {
  input.source_code != null
  src := lower(input.source_code)
  some marker in untrusted_input_markers
  contains(src, marker)
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

sql_source_prepare if {
  input.source_code != null
  src := lower(input.source_code)
  contains(src, sql_prepare_call_pattern)
}

sql_source_prepare if {
  flags := input.analysis_flags
  flags.sql_prepare_call_detected == true
}

sql_calls if {
  calls := input.graph_context.calls
  calls != null
  call := calls[_]
  call != null
  contains(lower(call), "java.sql.")
}

sql_calls if {
  flags := input.analysis_flags
  flags.sql_callable_statement_detected == true
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
  flags := input.analysis_flags
  flags.sql_dynamic_query_detected == true
}

sql_injection_heuristic if {
  servlet_context
  input.source_code != null
  sql_present
  src := lower(input.source_code)
  dynamic_source_construction(src)
  some kw in sql_keywords
  contains(src, kw)
  input_is_untrusted
}

dynamic_source_construction(src) if {
  contains(src, "+")
}

dynamic_source_construction(src) if {
  contains(src, ".append(")
  contains(src, "stringbuilder")
}

dynamic_source_construction(src) if {
  contains(src, ".append(")
  contains(src, "stringbuffer")
}

path_traversal_heuristic if {
  servlet_context
  flags := input.analysis_flags
  flags.path_traversal_detected == true
}

path_traversal_heuristic if {
  servlet_context
  input.source_code != null
  src := lower(input.source_code)
  input_is_untrusted
  dynamic_source_construction(src)
  some kw in file_path_keywords
  contains(src, kw)
}

command_injection_heuristic if {
  servlet_context
  flags := input.analysis_flags
  flags.command_injection_detected == true
}

command_injection_heuristic if {
  servlet_context
  input.source_code != null
  src := lower(input.source_code)
  input_is_untrusted
  dynamic_source_construction(src)
  some kw in command_keywords
  contains(src, kw)
}

ldap_injection_heuristic if {
  servlet_context
  flags := input.analysis_flags
  flags.ldap_injection_detected == true
}

ldap_injection_heuristic if {
  servlet_context
  input.source_code != null
  src := lower(input.source_code)
  input_is_untrusted
  dynamic_source_construction(src)
  some kw in ldap_keywords
  contains(src, kw)
}

xpath_injection_heuristic if {
  servlet_context
  flags := input.analysis_flags
  flags.xpath_injection_detected == true
}

xpath_injection_heuristic if {
  servlet_context
  input.source_code != null
  src := lower(input.source_code)
  input_is_untrusted
  dynamic_source_construction(src)
  some kw in xpath_keywords
  contains(src, kw)
}

violations[v] if {
  sql_injection_heuristic
  v := violation_record("ISO-A.8-SQL-INJECTION", "Possible SQL injection via string concatenation")
}

violations[v] if {
  path_traversal_heuristic
  v := violation_record("ISO-A.8-PATH-TRAVERSAL", "Possible path traversal via untrusted path construction")
}

violations[v] if {
  command_injection_heuristic
  v := violation_record("ISO-A.8-CMD-INJECTION", "Possible command injection via untrusted command construction")
}

violations[v] if {
  ldap_injection_heuristic
  v := violation_record("ISO-A.8-LDAP-INJECTION", "Possible LDAP injection via concatenated filter construction")
}

violations[v] if {
  xpath_injection_heuristic
  v := violation_record("ISO-A.8-XPATH-INJECTION", "Possible XPath injection via concatenated query construction")
}
