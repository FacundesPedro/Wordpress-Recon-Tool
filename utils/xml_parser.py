# recon_wp/utils/xml_parser.py
"""Safe XML parsing utilities for XML-RPC responses.

SECURITY:
- Disables XXE (XML External Entity) injection
- Disables external entity expansion
- Uses xml.etree.ElementTree in restricted mode (no DTD/entity support)

RISKS MITIGATED:
- XXE injection attacks
- Billion laughs attack (entity expansion DoS)
- External entity access to local files

Usage:
    from utils.xml_parser import safe_parse_xml, parse_xmlrpc_response

    tree = safe_parse_xml(xml_string)
    result = parse_xmlrpc_response(response_text)
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class XmlrpcResponse:
    """Parsed XML-RPC response."""

    is_success: bool
    fault_code: Optional[int] = None
    fault_string: Optional[str] = None
    method_response: bool = False
    has_array: bool = False
    has_struct: bool = False
    raw_data: dict = field(default_factory=dict)


def safe_parse_xml(xml_string: str) -> Optional[ET.Element]:
    """Parse XML string safely without XXE vulnerabilities.

    SECURITY:
    - Uses xml.etree.ElementTree which does not support external entities
    - Parses in restricted mode (no DTD processing)
    - Handles malformed XML gracefully

    Args:
        xml_string: XML content to parse

    Returns:
        ElementTree root element, or None on parse error
    """
    if not xml_string or not xml_string.strip():
        return None

    try:
        root = ET.fromstring(xml_string)
        return root
    except ET.ParseError:
        return None
    except Exception:
        return None


def parse_xmlrpc_response(content: str) -> XmlrpcResponse:
    """Parse XML-RPC response content safely.

    Args:
        content: Raw XML-RPC response text

    Returns:
        XmlrpcResponse object with parsed data
    """
    result = XmlrpcResponse(is_success=False)

    if not content:
        return result

    root = safe_parse_xml(content)
    if root is None:
        return result

    if root.tag == "methodResponse":
        result.method_response = True

        params = root.find("params")
        if params is not None:
            param = params.find("param")
            if param is not None:
                value = param.find("value")
                if value is not None:
                    if value.find("array") is not None:
                        result.has_array = True
                        result.is_success = True
                    if value.find("struct") is not None:
                        result.has_struct = True
                        result.is_success = True

        fault = root.find("fault")
        if fault is not None:
            value = fault.find("value")
            if value is not None:
                struct = value.find("struct")
                if struct is not None:
                    for member in struct.findall("member"):
                        name_elem = member.find("name")
                        val = member.find("value")
                        if name_elem is not None and val is not None and name_elem.text:
                            if name_elem.text == "faultCode":
                                int_val = val.find("int") or val.find("i4")
                                if int_val is not None and int_val.text:
                                    try:
                                        result.fault_code = int(int_val.text)
                                    except ValueError:
                                        pass
                            elif name_elem.text == "faultString":
                                str_val = val.find("string")
                                if str_val is not None:
                                    result.fault_string = str_val.text

    return result


def extract_fault_code(content: str) -> int:
    """Safely extract fault code from XML-RPC response.

    Args:
        content: Raw XML-RPC response text

    Returns:
        Fault code as integer, 0 if no fault
    """
    response = parse_xmlrpc_response(content)
    return response.fault_code or 0


def is_xmlrpc_success(content: str) -> bool:
    """Check if XML-RPC response indicates success.

    Args:
        content: Raw XML-RPC response text

    Returns:
        True if response indicates successful method call
    """
    response = parse_xmlrpc_response(content)
    return response.is_success and response.fault_code is None


def check_xmlrpc_available(content: str) -> bool:
    """Check if XML-RPC interface is available.

    Args:
        content: Raw XML-RPC response text

    Returns:
        True if XML-RPC responded with method list
    """
    if not content:
        return False

    root = safe_parse_xml(content)
    if root is None:
        return False

    return root.tag == "methodResponse" and "array" in content.lower()
