package iso27001

import rego.v1

sql_execute_pattern := "executequery("
sql_execute_update_pattern := "executeupdate("
sql_execute_generic_pattern := "execute("
sql_prepare_pattern := "preparestatement("
sql_prepare_call_pattern := "preparecall("
sql_keywords := {"select ", "insert ", "update ", "delete "}

file_path_keywords := {"../", "..\\", "fileinputstream", "new java.io.file(", "paths.get(", "new java.io.filereader("}
command_keywords := {"processbuilder", ".command(", "runtime.getruntime().exec(", "cmd.exe", "sh", "/c", "-c"}
ldap_keywords := {"initialdircontext", "dircontext", "ldapcontext", ".search("}
xpath_keywords := {"xpathfactory.newinstance(", ".compile(", ".evaluate("}
sql_execute_patterns := {sql_execute_pattern, sql_execute_update_pattern, sql_execute_generic_pattern}
sql_prepare_patterns := {sql_prepare_pattern, sql_prepare_call_pattern}

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

flag_enabled(name) if {
	flags := object.get(input, "analysis_flags", {})
	object.get(flags, name, false) == true
}

helper_summary_enabled(name) if {
	helpers := object.get(input, "helper_summaries", {})
	object.get(helpers, name, false) == true
}

no_analysis_flags if {
	input.analysis_flags == null
}

input_is_untrusted if {
	some marker in untrusted_input_markers
	source_contains(marker)
}

sql_source_exec if {
	source_contains_any(sql_execute_patterns)
}

sql_source_prepare if {
	source_contains_any(sql_prepare_patterns)
}

sql_source_prepare if {
	flag_enabled("sql_prepare_call_detected")
}

sql_calls if {
	graph_calls_contain("java.sql.")
}

sql_calls if {
	flag_enabled("sql_callable_statement_detected")
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
	flag_enabled("sql_dynamic_query_detected")
	flag_enabled("sql_query_uses_tainted_input")
	not helper_safe_sql
}

sql_injection_heuristic if {
	servlet_context
	helper_tainted_sql
	not helper_safe_sql
}

sql_injection_heuristic if {
	servlet_context
	no_analysis_flags
	input.source_code != null
	sql_present
	src := lower(input.source_code)
	dynamic_source_construction(src)
	some kw in sql_keywords
	contains(src, kw)
	input_is_untrusted
	not safe_prepared_statement_shape(src)
	not helper_safe_sql
}

safe_prepared_statement_shape(src) if {
	contains(src, "preparestatement(")
	contains(src, "?")
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

helper_safe_path if {
	helper_summary_enabled("safe_constant_return_used_in_path_sink")
}

helper_tainted_path if {
	helper_summary_enabled("tainted_return_used_in_path_sink")
}

helper_safe_ldap if {
	helper_summary_enabled("safe_constant_return_used_in_ldap_filter")
}

helper_tainted_ldap if {
	helper_summary_enabled("tainted_return_used_in_ldap_filter")
}

helper_safe_sql if {
	helper_summary_enabled("safe_constant_return_used_in_sql_query")
}

helper_safe_xpath if {
	helper_summary_enabled("safe_constant_return_used_in_xpath_query")
}

helper_safe_command if {
	helper_summary_enabled("safe_constant_return_used_in_command_sink")
}

helper_tainted_xpath if {
	helper_summary_enabled("tainted_return_used_in_xpath_query")
}

helper_tainted_sql if {
	helper_summary_enabled("tainted_return_used_in_sql_query")
}

helper_tainted_command if {
	helper_summary_enabled("tainted_return_used_in_command_sink")
}

path_traversal_heuristic if {
	servlet_context
	flag_enabled("path_traversal_detected")
	not helper_safe_path
}

path_traversal_heuristic if {
	servlet_context
	helper_tainted_path
	not helper_safe_path
}

path_traversal_heuristic if {
	servlet_context
	no_analysis_flags
	input.source_code != null
	src := lower(input.source_code)
	input_is_untrusted
	dynamic_source_construction(src)
	some kw in file_path_keywords
	contains(src, kw)
	not helper_safe_path
}

command_injection_heuristic if {
	servlet_context
	flag_enabled("command_exec_string_tainted")
	not helper_safe_command
}

command_injection_heuristic if {
	servlet_context
	flag_enabled("command_exec_args_tainted")
	not helper_safe_command
}

command_injection_heuristic if {
	servlet_context
	flag_enabled("command_env_only_tainted")
	not helper_safe_command
}

command_injection_heuristic if {
	servlet_context
	helper_tainted_command
	not helper_safe_command
}

command_injection_heuristic if {
	servlet_context
	no_analysis_flags
	input.source_code != null
	src := lower(input.source_code)
	input_is_untrusted
	dynamic_source_construction(src)
	some kw in command_keywords
	contains(src, kw)
	not helper_safe_command
}

ldap_injection_heuristic if {
	servlet_context
	flag_enabled("ldap_injection_detected")
	not helper_safe_ldap
}

ldap_injection_heuristic if {
	servlet_context
	helper_tainted_ldap
	not helper_safe_ldap
}

ldap_injection_heuristic if {
	servlet_context
	no_analysis_flags
	input.source_code != null
	src := lower(input.source_code)
	input_is_untrusted
	dynamic_source_construction(src)
	some kw in ldap_keywords
	contains(src, kw)
	not helper_safe_ldap
}

xpath_injection_heuristic if {
	servlet_context
	flag_enabled("xpath_injection_detected")
	not helper_safe_xpath
}

xpath_injection_heuristic if {
	servlet_context
	helper_tainted_xpath
	not helper_safe_xpath
}

xpath_injection_heuristic if {
	servlet_context
	input.source_code != null
	src := lower(input.source_code)
	input_is_untrusted
	dynamic_source_construction(src)
	some kw in xpath_keywords
	contains(src, kw)
	not helper_safe_xpath
	not flag_enabled("xpath_query_uses_safe_constant")
}

# ---------------------------------------------------------------------------
# Graph-aware multi-hop taint path detection
#
# taint_path_confirmed_for(sink_type) is true when build_evidence_bundle has
# populated input.taint_paths with a path reaching the requested sink.
# Combining this with input_is_untrusted (the method reads from HTTP input)
# lets us detect injection chains that span two or more user-code methods.
# The existing helper_safe_* suppressors still apply.
# ---------------------------------------------------------------------------

taint_path_confirmed_for(sink_type) if {
	input.taint_paths != null
	some path in input.taint_paths
	path.sink_type == sink_type
}

sql_injection_heuristic if {
	servlet_context
	input_is_untrusted
	taint_path_confirmed_for("sql")
	not helper_safe_sql
}

path_traversal_heuristic if {
	servlet_context
	input_is_untrusted
	taint_path_confirmed_for("path")
	not helper_safe_path
}

command_injection_heuristic if {
	servlet_context
	input_is_untrusted
	taint_path_confirmed_for("command")
	not helper_safe_command
}

ldap_injection_heuristic if {
	servlet_context
	input_is_untrusted
	taint_path_confirmed_for("ldap")
	not helper_safe_ldap
}

xpath_injection_heuristic if {
	servlet_context
	input_is_untrusted
	taint_path_confirmed_for("xpath")
	not helper_safe_xpath
}

violations contains violation_record("ISO-A.8-SQL-INJECTION", "Possible SQL injection via string concatenation") if {
	sql_injection_heuristic
}

violations contains violation_record("ISO-A.8-PATH-TRAVERSAL", "Possible path traversal via untrusted path construction") if {
	path_traversal_heuristic
}

violations contains violation_record("ISO-A.8-CMD-INJECTION", "Possible command injection via untrusted command construction") if {
	command_injection_heuristic
}

violations contains violation_record("ISO-A.8-LDAP-INJECTION", "Possible LDAP injection via concatenated filter construction") if {
	ldap_injection_heuristic
}

violations contains violation_record("ISO-A.8-XPATH-INJECTION", "Possible XPath injection via concatenated query construction") if {
	xpath_injection_heuristic
}
