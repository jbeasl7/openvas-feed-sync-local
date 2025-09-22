# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Returns an array of common (client-side) HTTP headers having the given value added to each
#        of the header (created internally by @ref http_hdr_get_common_list). This function can be
#        used to e.g. add the very same payload to every known / common header.
#
# @note No ":" header key/value separator needs to be given to the "value" parameter.
#
# @param value            The (mandatory) value/payload to add to the HTTP headers.
# @param header_list      A (optional) list of headers to which the passed value should be added. If
#                         none is given the function is falling back to the internal list of
#                         @ref http_hdr_get_common_list
# @param exclude_hdr_list A (optional) list of headers which should be excluded like e.g.
#                         exclude_hdr:make_list("User-Agent"). This can be used if e.g. a specific
#                         header is handled separately in the VT calling this function.
#                         Note: If a list of headers is passed via the "header_list" parameter this
#                         excluded list will be ignored.
#
# @return An array containing the HTTP headers in the array keys and the passed values in the array
#         value of each key, NULL otherwise if the "value" parameter has been left empty or data has
#         been passed to the "exclude_hdr_list" parameter but the data isn't a list.
#
function http_hdr_add_value( value, header_list, exclude_hdr_list ) {

  local_var value, header_list, exclude_hdr_list;
  local_var hdr_list, ret_array, _hdr;

  if( ! value ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#value#-#http_hdr_add_value" );
    return;
  }

  if( exclude_hdr_list && ! is_array( exclude_hdr_list ) ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_hdr_add_value(): No list passed in 'exclude_hdr_list' parameter" );
    return;
  }

  if( header_list && ! is_array( header_list ) ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_hdr_add_value(): No list passed in 'header_list' parameter" );
    return;
  }

  if( header_list ) {
    hdr_list = header_list;
  } else {
    hdr_list = http_hdr_get_common_list( exclude_hdr_list:exclude_hdr_list );
    if( ! hdr_list ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_hdr_add_value(): Failed to craft header list via http_hdr_get_common_list() for unknown reasons" );
      return;
    }
  }

  ret_array = make_array();

  foreach _hdr( hdr_list )
    ret_array[_hdr] = value;

  return ret_array;
}

# @brief Returns a list of common (client-side) HTTP headers.
#
# @param exclude_hdr_list A (optional) list of headers which should be excluded like e.g.
#                         exclude_hdr:make_list("User-Agent"). This can be used if e.g. a specific
#                         header is handled separately in the VT calling this function.
#
# @return A list containing common HTTP headers, NULL otherwise if data has been passed to the
#         "exclude_hdr_list" parameter but the data isn't a list.
#
function http_hdr_get_common_list( exclude_hdr_list ) {

  # nb: Keep this function at the bottom of this include as it might get even longer in the future
  # which would make the include hard to read if it starts with a function having many lines.

  local_var exclude_hdr_list;
  local_var tmp_hdr_list, final_hdr_list, _hdr;

  if( exclude_hdr_list && ! is_array( exclude_hdr_list ) ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#http_hdr_get_common_list(): No list passed in 'exclude_hdr_list' parameter" );
    return;
  }

  tmp_hdr_list = make_list(
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Access-Control-Request-Headers",
    "Access-Control-Request-Method",
    "Authorization",
    "Cache-Control",
    "Content-Type",
    "Cookie",
    "If-Modified-Since",
    "Location",
    "Origin",
    "Pragma",
    "Referer",
    "Upgrade-Insecure-Requests",
    "User-Agent",
    "X-Api-Version",                  # nb: Seen in various Log4Shell PoCs
    "X-CSRF-Token",
    "X-Druid-Comment",
    "X-Forwarded-Prefix",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Server",
    "X-Forwarded-Scheme",
    "X-Log",                          # As used in e.g. https://github.com/tothi/log4shell-vulnerable-app
    "X-Origin",
    "X-Original-URL"
  );

  if( exclude_hdr_list ) {
    final_hdr_list = make_list();
    foreach _hdr( tmp_hdr_list ) {
      if( ! in_array( search:_hdr, array:exclude_hdr_list, part_match:FALSE, icase:TRUE ) ) {
        final_hdr_list = make_list( final_hdr_list, _hdr );
      }
    }
  } else {
    final_hdr_list = tmp_hdr_list;
  }

  return final_hdr_list;
}
