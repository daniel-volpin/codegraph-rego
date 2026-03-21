import unittest

from codegraph.policy.helper_summaries import HelperMethodAnalyzer


class TestHelperMethodAnalyzer(unittest.TestCase):
    def test_marks_safe_constant_return(self) -> None:
        source = (
            "private String doSomething(String param) {"
            'String bar = "safe!";'
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertTrue(summary.returns_constant_string)
        self.assertFalse(summary.propagates_tainted_input)

    def test_marks_tainted_param_return(self) -> None:
        source = (
            "private String doSomething(String param) {"
            "String bar = param;"
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertFalse(summary.returns_constant_string)
        self.assertTrue(summary.propagates_tainted_input)

    def test_constant_true_if_else_prefers_tainted_branch(self) -> None:
        source = (
            "private String doSomething(String param) {"
            "String bar;"
            "int num = 196;"
            'if ((500 / 42) + num > 200) bar = param; else bar = "This should never happen";'
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertFalse(summary.returns_constant_string)
        self.assertTrue(summary.propagates_tainted_input)

    def test_constant_true_if_else_prefers_constant_branch(self) -> None:
        source = (
            "private String doSomething(String param) {"
            "String bar;"
            "int num = 86;"
            'if ((7 * 42) - num > 200) bar = "This_should_always_happen"; else bar = param;'
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertTrue(summary.returns_constant_string)
        self.assertFalse(summary.propagates_tainted_input)

    def test_map_get_safe_override_is_constant(self) -> None:
        source = (
            "private String doSomething(String param) {"
            'String bar = "safe!";'
            "java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();"
            'map.put("keyA", "a_Value");'
            'map.put("keyB", param);'
            'bar = (String) map.get("keyB");'
            'bar = (String) map.get("keyA");'
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertTrue(summary.returns_constant_string)
        self.assertFalse(summary.propagates_tainted_input)

    def test_map_get_tainted_value_is_tainted(self) -> None:
        source = (
            "private String doSomething(String param) {"
            'String bar = "safe!";'
            "java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();"
            'map.put("keyA", "a_Value");'
            'map.put("keyB", param);'
            'bar = (String) map.get("keyB");'
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertFalse(summary.returns_constant_string)
        self.assertTrue(summary.propagates_tainted_input)

    def test_list_safe_tail_value_is_constant(self) -> None:
        source = (
            "private String doSomething(String param) {"
            'String bar = "alsosafe";'
            "java.util.List<String> valuesList = new java.util.ArrayList<String>();"
            'valuesList.add("safe");'
            "valuesList.add(param);"
            'valuesList.add("moresafe");'
            "valuesList.remove(0);"
            "bar = valuesList.get(1);"
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertTrue(summary.returns_constant_string)
        self.assertFalse(summary.propagates_tainted_input)


if __name__ == "__main__":
    unittest.main()
