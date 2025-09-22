# SPDX-FileCopyrightText: 2004 Tenable Network Security
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

function line2string( line, linenumber ) {

  local_var line, linenumber;
  local_var tmp, pos;

  if( isnull( line ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#line#-#line2string" );

  line = line * 16;

  tmp = raw_string( ( line >> 24 ) & 0xFF,
                    ( line >> 16 ) & 0xFF,
                    ( line >> 8 ) & 0xFF,
                    ( line ) & 0xFF );

  if( linenumber < 256 ) {
    pos = 3;
  } else if( linenumber < 65536) {
    pos = 2;
  } else if( linenumber < 16777216 ) {
    pos = 1;
  } else {
    pos = 0;
  }

  return string( "0x", toupper( hexstr( substr( tmp, pos, 3 ) ) ), ": " );
}

# @brief Checks if a passed character is a printable one (Range from >= 0x20 and <= 0x7E).
#
# @param c The character to check.
#
# @return TRUE if the passed character is a printable one, FALSE otherwise and NULL if no char was
#         passed to the c parameter.
#
function isprint( c ) {

  local_var c;

  if( isnull( c ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#c#-#isprint" );
    return NULL;
  }

  if( ( ord( c ) >= 0x20 ) && ( ord( c ) <= 0x7E ) ) {
    return TRUE;
  } else {
    return FALSE;
  }
}

function hexdump( ddata ) {

  local_var ddata;
  local_var len, linenumber, i, line, data, j, c, tmp;

  if( isnull( ddata ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#ddata#-#hexdump" );

  len = strlen( ddata );
  linenumber = len / 16;

  for( i = 0; i <= linenumber; i++ ) {

    line = line2string( line:i, linenumber:len );
    data = "";

    for( j = 0; j < 16; j++ ) {
      if( ( i*16 + j ) < len ) {
        line += string(" ", toupper( hexstr( ddata[i*16+j] ) ) );

        c = ddata[i*16+j];

        if( isprint( c:c ) ) {
          data += c;
        } else {
          data += ".";
        }
      } else {
        line += "   ";
        data += " ";
      }
    }

    tmp += string( line, "    ", data, "\n" );
  }

  return tmp;
}

function dump( dtitle, ddata ) {

  local_var dtitle, ddata;

  if( isnull( ddata ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#ddata#-#dump" );

  if( ! isnull( dtitle ) ) display( '---[ ' + dtitle + ' ]---\n' );

  display( hexdump( ddata:ddata ) );
}
