# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Returns a XML "opening" tag and adds passed additional attributes to the tag.
#
# @param tag        the tag to use as a XML tag, e.g. test to create a tag like <test>
# @param attributes the attributes to add to the tag (optional), this needs to be passed as an array
#                   which was created in the form of e.g. attributes['attributename'] = 'attributevalue';
#
# @return A string containing a XML representation of the passed parameters or NULL if
#         an empty tag parameter was passed or no array was passed to the attributes parameter.
#
#         Example:
#         str = "tagname";
#         attr_array['attributename'] = 'attributevalue';
#         xml_open_tag(tag:str, attributes:attr_array);
#
#         Result:
#         <tagname attributename="attributevalue">
#
function xml_open_tag(tag, attributes) {

  local_var tag, attributes;
  local_var res, _attr;

  if(isnull(tag)) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tag#-#xml_open_tag");
    return NULL;
  }

  if(attributes && typeof(attributes) != "array") {
    set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#xml_open_tag: attributes parameter not empty but no array passed.");
    return NULL;
  }

  res = '';

  res += '<' + tag;

  if(!isnull(attributes)) {
    foreach _attr(keys(attributes)) {
      res += ' ' + _attr + '="' + xml_escape(str:attributes[_attr]) + '"';
    }
  }
  res += '>';
  return res;
}

# @brief Returns a XML "closing" tag.
#
# @param tag the tag to use as a XML tag, e.g. test to create a tag like </test>
#
# @return A string containing a XML representation of the passed parameters or
#         NULL if an empty tag parameter was passed.
#
#         Example: xml_close_tag(tag:"tagname");
#         Result: </tagname>
#
function xml_close_tag(tag) {

  local_var tag;

  if (isnull(tag)) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tag#-#xml_close_tag");
    return NULL;
  }

  return '</' + tag + '>';
}

# @brief Returns a complete XML representation of various passed data in one single string "line".
#
# @param tag        the tag to use as a XML tag, e.g. test to use a tag like <test></test>
# @param attributes the attributes to add to the tag (optional), this needs to be passed as an array
#                   which was created in the form of e.g. attributes['attributename'] = 'attributevalue';
# @param value      the value to add within the XML tag (optional), e.g. <test>value</test>
#
# @return A string containing a XML representation of the passed parameters or NULL if
#         an empty tag parameter was passed.
#
#         Example:
#         tagstr = "tagname";
#         tagval = "tagvalue";
#         attr_array['attributename'] = 'attributevalue';
#         xml_tagline(tag:tagstr, attributes:attr_array, value:tagval);
#
#         Result:
#         <tagname attributename="attributevalue">tagvalue</tagname>
#
function xml_tagline(tag, attributes, value) {

  local_var tag, attributes, value;

  if (isnull(tag)) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tag#-#xml_tagline");
    return NULL;
  }

  if (attributes && typeof(attributes) != "array") {
    set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#xml_tagline: attributes parameter not empty but no array passed.");
    return NULL;
  }

  return xml_open_tag(tag:tag, attributes:attributes) + xml_escape(str:value) + xml_close_tag(tag:tag);
}

# @brief Returns the XML representation of an opened XML comment.
#
# @return A string containing the XML representation of an opened XML comment.
#
function xml_open_comment() {
  return '<!--';
}

# @brief Returns the XML representation of a closed XML comment.
#
# @return A string containing the XML representation of a closed XML comment.
#
function xml_close_comment() {
  return '-->';
}

# @brief Returns the XML representation of a XML newline.
#
# @return A string containing the XML representation of a XML newline.
#
function xml_newline() {
  return '\n';
}

# @brief Evaluates a passed string for reserved XML (namely &, ", ', < or >) chars which needs to be
#        escaped and returns representation of the passed string with those chars escaped.
#
# @param str the string to evaluate
#
# @return A string containing the representation of the passed string with escaped chars or NULL if
#         an empty str parameter was passed.
#
function xml_escape(str) {

  local_var str;
  local_var escape_table, str_escaped, max_idx, i;

  if(isnull(str)) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#str#-#xml_escape");
    return NULL;
  }

  escape_table = make_array(
    "&", "&amp;",
    "'", "&apos;",
    '"', "&quot;",
    "<", "&lt;",
    ">", "&gt;");

  str_escaped = "";

  max_idx = strlen(str);

  for(i = 0; i < max_idx; i++) {
    if(!isnull(escape_table[str[i]]))
      str_escaped += escape_table[str[i]];
    else
      str_escaped += str[i];
  }
  return str_escaped;
}
