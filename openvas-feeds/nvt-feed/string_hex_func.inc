# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some functions might have been moved from misc_func.inc into this
# include and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Enables debugging output for a few functions below
global_var _string_hex_func_debug;
_string_hex_func_debug = 0;

# hex2raw was written by Renaud?
# nb: The previous "url_hex2raw" from url_func.inc (which was a copy of this function)
# had the following comment:
# function taken from amap.nasl which is GPL
function hex2raw( s ) {

  local_var s;
  local_var l, i, j, ret;

  if( isnull( s ) )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#s#-#hex2raw" );

  s = chomp( s ); # remove trailing blanks, CR, LF...
  l = strlen( s );
  if( l % 2 ) {
    if( _string_hex_func_debug ) display( "hex2raw: odd string: ", s, "\n" );
    l--;
  }
  s = tolower( s );
  for( i = 0; i < l; i += 2 ) {
    if( ord( s[i] ) >= ord( "0" ) && ord( s[i] ) <= ord( "9" ) )
      j = int( s[i] );
    else
      j = int( ( ord( s[i] ) - ord( "a" ) ) + 10 );

    j *= 16;
    if( ord( s[i + 1] ) >= ord( "0" ) && ord( s[ i + 1] ) <= ord( "9" ) )
      j += int( s[i+1] );
    else
      j += int( ( ord( s[ i + 1 ] ) - ord( "a" ) ) + 10 );
    ret += raw_string( j );
  }
  return ret;
}

# @brief Creates an Universally Unique Identifier (UUID) in version 4 (random).
#
# @note This is a very rudimentary implementation of version 4 and should be eventually replaced by
#       an external library (e.g. in the scanner / NASL libraries).
#
# @note https://en.wikipedia.org/wiki/Universally_unique_identifier#Version_4_(random)
#
# @note You need to include misc_func.inc due to the usage of @ref rand_str
#
# @return A string containing a UUIDv4

function create_uuid() {

  local_var charset, uuid;

  # While it seems that services should also accept uppercase chars according to some RFCs the lower
  # case variant is preferred and has been used here...
  charset = "0123456789abcdef";

  uuid  = rand_str( length:8, charset:charset );
  uuid += "-";
  uuid += rand_str( length:4, charset:charset );
  uuid += "-";
  # nb: Version 4
  uuid += "4";
  uuid += rand_str( length:3, charset:charset );
  uuid += "-";
  # nb: 8, 9, A or B for the 2 bit indication
  uuid += rand_str( length:1, charset:"89ab" );
  uuid += rand_str( length:3, charset:charset );
  uuid += "-";
  uuid += rand_str( length:12, charset:charset );

  return uuid;
}
