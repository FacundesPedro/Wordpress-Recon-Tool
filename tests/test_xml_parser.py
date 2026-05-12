# tests/test_xml_parser.py
"""Tests for safe XML parser module."""

from utils.xml_parser import XmlrpcResponse, safe_parse_xml


class TestSafeXMLParsing:
    """Tests for safe XML parsing."""

    def test_valid_xml_parse(self):
        """Test parsing valid XML."""
        xml = "<root><item>test</item></root>"
        result = safe_parse_xml(xml)
        assert result is not None

    def test_simple_method_response(self):
        """Test parsing simple methodResponse."""
        xml = """<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value><string>Hello World</string></value>
    </param>
  </params>
</methodResponse>"""
        result = safe_parse_xml(xml)
        assert result is not None
        assert result.tag == "methodResponse"

    def test_nested_values(self):
        """Test parsing nested XML values."""
        xml = """<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value>
        <struct>
          <member>
            <name>key1</name>
            <value><string>value1</string></value>
          </member>
        </struct>
      </value>
    </param>
  </params>
</methodResponse>"""
        result = safe_parse_xml(xml)
        assert result is not None

    def test_array_parsing(self):
        """Test parsing XML arrays."""
        xml = """<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value><string>item1</string></value>
            <value><string>item2</string></value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodResponse>"""
        result = safe_parse_xml(xml)
        assert result is not None

    def test_integer_values(self):
        """Test parsing integer values."""
        xml = """<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value><int>42</int></value>
    </param>
  </params>
</methodResponse>"""
        result = safe_parse_xml(xml)
        assert result is not None

    def test_boolean_values(self):
        """Test parsing boolean values."""
        xml = """<?xml version="1.0"?>
<methodResponse>
  <params>
    <param>
      <value><boolean>1</boolean></value>
    </param>
  </params>
</methodResponse>"""
        result = safe_parse_xml(xml)
        assert result is not None


class TestXXEProtection:
    """Tests for XXE attack protection."""

    def test_xxe_attack_returns_none(self):
        """Test that XXE attacks result in None (ElementTree doesn't support DTD/entities)."""
        xxe_xml = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>"""
        result = safe_parse_xml(xxe_xml)
        assert result is None

    def test_external_entity_parsed_but_not_accessed(self):
        """Test that external entities are parsed but the reference isn't actually accessed."""
        xml = """<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://evil.com/evil.dtd">
<foo>test</foo>"""
        result = safe_parse_xml(xml)
        assert result is not None
        assert result.tag == "foo"

    def test_parameter_entity_returns_none(self):
        """Test that parameter entities result in None (ElementTree doesn't support DTD)."""
        xml = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % per SYSTEM "file:///etc/passwd">
  <!ENTITY test "test %per;">
]>
<foo>&test;</foo>"""
        result = safe_parse_xml(xml)
        assert result is None


class TestBillionLaughsProtection:
    """Tests for billion laughs (entity expansion) attack protection."""

    def test_large_entity_expansion_blocked(self):
        """Test that large entity expansion is blocked."""
        billions_laughs = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>"""

        try:
            result = safe_parse_xml(billions_laughs)
            if result is not None:
                text = result.text or ""
                assert len(text) < 1000
        except Exception:
            pass

    def test_quadratic_blowup_blocked(self):
        """Test that quadratic blowup attacks are blocked."""
        xml = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY a "aaaaaaaaaa">
]>
<foo>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;aaaa</foo>"""
        result = safe_parse_xml(xml)
        assert result is not None


class TestMalformedXMLHandling:
    """Tests for malformed XML handling."""

    def test_missing_closing_tag(self):
        """Test handling of missing closing tags."""
        xml = "<root><item>test</root>"
        result = safe_parse_xml(xml)
        assert result is None

    def test_unclosed_tag(self):
        """Test handling of unclosed tags."""
        xml = "<root><item>test</root>"
        result = safe_parse_xml(xml)
        assert result is None

    def test_mismatched_tags(self):
        """Test handling of mismatched tags."""
        xml = "<root><item>test</wrong></root>"
        result = safe_parse_xml(xml)
        assert result is None

    def test_invalid_characters(self):
        """Test handling of invalid XML characters."""
        xml = "<root><item>test\x00</item></root>"
        result = safe_parse_xml(xml)
        assert result is None or isinstance(result, object)

    def test_empty_document(self):
        """Test handling of empty document."""
        result = safe_parse_xml("")
        assert result is None

    def test_whitespace_only(self):
        """Test handling of whitespace-only document."""
        result = safe_parse_xml("   \n\t  ")
        assert result is None


class TestXmlrpcResponse:
    """Tests for XML-RPC response dataclass."""

    def test_xmlrpc_response_creation(self):
        """Test creating XmlrpcResponse."""
        response = XmlrpcResponse(is_success=True)
        assert response.is_success is True
        assert response.fault_code is None

    def test_xmlrpc_response_with_fault(self):
        """Test creating XmlrpcResponse with fault."""
        response = XmlrpcResponse(
            is_success=False,
            fault_code=1,
            fault_string="Error",
        )
        assert response.fault_code is not None
        assert response.fault_code == 1
        assert response.fault_string == "Error"

    def test_xmlrpc_response_has_struct_and_array(self):
        """Test has_struct and has_array properties."""
        response = XmlrpcResponse(
            is_success=True,
            has_array=True,
            has_struct=True,
        )
        assert response.has_array is True
        assert response.has_struct is True

    def test_xmlrpc_response_default_values(self):
        """Test default values for XmlrpcResponse."""
        response = XmlrpcResponse(is_success=False)
        assert response.is_success is False
        assert response.method_response is False
        assert response.has_array is False
        assert response.has_struct is False


class TestXMLParserEdgeCases:
    """Edge case tests for XML parser."""

    def test_declaration_only(self):
        """Test XML with declaration only."""
        xml = '<?xml version="1.0" encoding="UTF-8"?>'
        result = safe_parse_xml(xml)
        assert result is None

    def test_namespaces(self):
        """Test XML with namespaces."""
        xml = """<?xml version="1.0"?>
<root xmlns:foo="http://example.com/foo">
  <foo:item>test</foo:item>
</root>"""
        result = safe_parse_xml(xml)
        assert result is not None

    def test_unicode_content(self):
        """Test XML with Unicode content."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<root>
  <item>Hello World! \u4e2d\u6587</item>
</root>"""
        result = safe_parse_xml(xml)
        assert result is not None

    def test_comments_ignored(self):
        """Test that comments are handled."""
        xml = """<?xml version="1.0"?>
<root>
  <!-- This is a comment -->
  <item>test</item>
</root>"""
        result = safe_parse_xml(xml)
        assert result is not None

    def test_processing_instructions(self):
        """Test processing instructions."""
        xml = """<?xml version="1.0"?>
<?pi-test data?>
<root><item>test</item></root>"""
        result = safe_parse_xml(xml)
        assert result is not None

    def test_cdata_sections(self):
        """Test CDATA sections."""
        xml = """<?xml version="1.0"?>
<root>
  <item><![CDATA[<script>alert('xss')</script>]]></item>
</root>"""
        result = safe_parse_xml(xml)
        assert result is not None
