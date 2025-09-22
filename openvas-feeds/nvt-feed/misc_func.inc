# SPDX-FileCopyrightText: 2002 Michel Arboi
# SPDX-FileCopyrightText: New code / functions since 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

function rand_str( length, charset ) {

  local_var length, charset;
  local_var l, s, i, n;

  if( ! charset )
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

  if( isnull( length ) )
    length = 8;

  l = strlen( charset );
  s = "";
  for( i = 0; i < length; i++ ) {
    n = rand() % l;
    s += charset[n];
  }
  return s;
}

function base64_decode( str, key_str ) {

  local_var str, key_str;
  local_var len, ret, base64, i, b64, j, c, a, b, o, k;

  if( isnull( str ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#str#-#base64_decode" );

  len = strlen( str );
  ret = "";

  if( key_str )
    base64 = key_str;
  else
    base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  for( i = 0; i < 256; i++ )
    b64[i] = 0;
  for( i = 0; i < strlen( base64 ); i++ )
    b64[ord( base64[i] )] = i;

  for( j = 0; j < len; j += 4 ) {
    for( i = 0; i < 4; i++ ) {
      c = ord( str[j + i] );
      a[i] = c;
      b[i] = b64[c];
    }

    o[0] = ( b[0] << 2 ) | ( b[1] >> 4 );
    o[1] = ( b[1] << 4 ) | ( b[2] >> 2 );
    o[2] = ( b[2] << 6 ) | b[3];
    if( a[2] == ord( '=' ) ) {
     i = 1;
    } else if( a[3] == ord( '=' ) ) {
     i = 2;
    } else {
     i = 3;
    }
    for( k = 0; k < i; k++ )
      ret += raw_string( int( o[k] ) & 255 );

    if( i < 3 )
      break;
  }

  return ret;
}

function base64_code( c ) {

  local_var c;
  local_var __base64_code;

  __base64_code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  if( isnull( c ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#c#-#base64_code" );

  return( __base64_code[c] );
}

function pow2( x ) {

  local_var x;
  local_var __ret;

  if( isnull( x ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#x#-#pow2" );

  __ret = 1;
  while( x ) {
    __ret = __ret * 2;
    x = x  - 1;
  }
  return( __ret );
}

function base64( str ) {

  local_var str;
  local_var len, i, ret, char_count, _bits, val, cnt, mul;

  if( isnull( str ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#str#-#base64" );

  len = strlen( str );
  i = 0;
  ret = "";
  char_count = 0;
  _bits = 0;

  while( i < len ) {
    _bits = _bits + ord( str[i] );
    char_count = char_count + 1;
    if( char_count == 3 ) {
      val = _bits / 262144;
      ret = string( ret, base64_code( c:val ) );
      val = _bits / 4096;
      val = val & 0x3F;
      ret = string( ret, base64_code( c:val ) );
      val = _bits / 64;
      val = val & 0x3F;
      ret = string( ret, base64_code( c:val ) );
      val = _bits & 0x3F;
      ret = string( ret, base64_code( c:val ) );
      char_count = 0;
      _bits = 0;
    } else {
      _bits = _bits * 256;
    }
    i = i + 1;
  }

  if( ! ( char_count == 0 ) ) {
    cnt = char_count * 8;
    mul = 16;
    mul = mul - cnt;
    mul = pow2( x:mul );
    _bits = _bits * mul;
    val = _bits / 262144;
    ret = string( ret, base64_code( c:val ) );
    val = _bits / 4096;
    val = val & 0x3F;
    ret = string( ret, base64_code( c:val ) );
    if( char_count == 1 ) {
      ret = string(ret, "==");
    } else {
      val = _bits / 64;
      val = val & 0x3F;
      ret = string( ret, base64_code( c:val ), "=" );
    }
  }
  return( ret );
}


# This function converts a string representing a decimal number to
# to hexadecimal; eg, dec2hex(1098757090) == "417db3e2".
#
# Args:
#   o num, decimal number.
#
# Return:
#   hex number represented as a raw string.
#
# updated: 16-Nov-2004, George A. Theall
#
function dec2hex( num ) {

  local_var num;
  local_var hex, rem, num;

  if( isnull ( num ) ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#num#-#dec2hex" );

  hex = "";

  num = int( num );
  while( num > 0 ) {
    rem = num % 256;
    hex = raw_string( rem, hex );
    num = num / 256;
    if( num > 0 && num < 255 ) {
      hex = raw_string( num, hex );
      num = 0;
    }
  }
  if( ! hex ) hex = raw_string( 0x00 );

  return hex;
}

# from packeteer_web_login.nasl
function hex2str() {

  local_var hs, s, i, xlat, j;

  hs = _FCT_ANON_ARGS[0];

  if( isnull( hs ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#hex2str" );
    return;
  }

  s = "";
  for( i = 0; i < 256; ++i )
    xlat[ tolower( substr( hex( i ), 2 ) ) ] = raw_string( i );

  for( j = 0; j < strlen( hs ) / 2; ++j )
    s += xlat[ tolower( substr( hs, 2 * j, 2 * j + 1 ) ) ];

  return s;
}

# "if( is_printer_mac( mac:mac ) ) do something..."
# include mac_prefix.inc if you want to use this function
function is_printer_mac( mac ) {

  local_var mac;
  local_var mac_s, p_vendors, max_prefix, mac_vendor, _pv;

  if( ! mac ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#mac#-#is_printer_mac" );
    return;
  }

  mac_s = split( mac, sep:":", keep:FALSE );
  if( max_index( mac_s ) != 6 ) return;

  p_vendors = make_list( "xerox", "canon", "kyocera", "lexmark", "hewlettp", "samsung" );

  mac_prefix = toupper( mac_s[0] + ':' + mac_s[1] + ':' + mac_s[2] );

  mac_vendor = tolower( mac_prefixes[ mac_prefix ] );
  if( ! mac_vendor ) return;

  foreach _pv( p_vendors )
    if( mac_vendor == _pv )
      return TRUE;

  return;
}

# @brief Removes any non-printable characters in a passed data/string (default) or replaces
#        it with a specified replacement string passed to this function.
#
# @param ddata               The data to evaluate.
# @param noprint_replacement An (optional) char/string to be use to replace the non-printable
#                            chars with. If not passed the non-printable char will be removed
#                            instead.
#
# @return A string with the removed/replaced non-printable chars or NULL if no ddata parameter
#         was passed.
#
function bin2string( ddata, noprint_replacement ) {

  local_var ddata, noprint_replacement;
  local_var len, linenumber, i, data, j, c, tmp;

  if( isnull( ddata ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#ddata#-#bin2string" );
    return NULL;
  }

  len = strlen( ddata );
  linenumber = len / 16;

  for( i = 0; i <= linenumber; i++ ) {

    data = "";

    for( j = 0; j < 16; j++ ) {
      if( ( i*16+j ) < len ) {
        c = ddata[i*16+j];

        if( isprint( c:c ) ) {
          data += c;
        } else {
          if( ! isnull( noprint_replacement ) ) {
            data += noprint_replacement;
          }
        }
      }
   }
   tmp += string( data );
  }
  return tmp;
}

# modified unicode4 from smb_nt.inc
function ascii2unicode( data ) {

  local_var data;
  local_var len, i, ret;

  if( isnull( data ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#ascii2unicode" );
    return;
  }

  len = strlen( data );

  for( i = 0; i < len; i++ ) {
    ret += data[i] + raw_string( 0x00 );
  }
  return ret;
}

# @brief Creates a formatted and sorted table (with two columns) from
#        the info given in the passed array. All array keys are
#        included in the first column and the matching array values
#        in the second column.
#
# @param array        The array to use as a base for the formatted table.
# @param sep          A (optional) separator which should be used between
#                     each column. Defaults to " : " if not given.
# @param columnheader The (optional) headers which should be included above
#                     each column. This needs to be passed in form of a list
#                     like e.g. columnheader:make_list("Column 1", "Column 2");
# @param maxentries   An (optional) amount of entries of the array which should
#                     be included in the created table.
#
# @return A string with the formatted and sorted table or NULL if
#         no array was given.
#
function text_format_table( array, sep, columnheader, maxentries ) {

  local_var array, sep, columnheader, maxentries;
  local_var currententries, _key, len, maxlen, hascolumnheader, columnheaderlen, fulllen, seplen, value, flen, paddinglen, valuelen, report, reportheader, reportheaderlen;

  if( ! array ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#array#-#text_format_table" );
    return;
  }

  if( ! is_array( array ) ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#text_format_table: No array passed in 'array' parameter" );
    return;
  }

  if( isnull( sep ) )
    sep = " : ";

  currententries = 0;
  foreach _key( sort( keys( array ) ) ) {

    currententries++;
    if( maxentries > 0 && currententries > maxentries )
      break;

    _key = chomp( _key );
    _key = ereg_replace( string:_key, pattern:'[\r\n]+', replace:"<newline>" );
    len = strlen( _key );

    if( ! maxlen ) {
      maxlen = len;
      continue;
    }

    if( maxlen < len )
      maxlen = len;
  }

  if( columnheader && is_array( columnheader ) ) {
    hascolumnheader = TRUE;
    columnheaderlen = strlen( chomp( columnheader[0] ) );
    if( maxlen < columnheaderlen )
      maxlen = columnheaderlen;
  }

  currententries = 0;
  fulllen = 0;
  seplen = strlen( sep );
  foreach _key( sort( keys( array ) ) ) {

    currententries++;
    if( maxentries > 0 && currententries > maxentries )
      break;

    value = array[_key]; # nb: This needs to be placed before the chomp() on _key because the it wouldn't match anything afterwards.
    _key = chomp( _key );
    _key = ereg_replace( string:_key, pattern:'[\r\n]+', replace:"<newline>" );
    flen = strlen( _key );
    paddinglen = ( maxlen - flen );
    value = chomp( value );
    value = ereg_replace( string:value, pattern:'[\r\n]+', replace:"<newline>" );
    valuelen = strlen( value );

    report += _key + crap( data:" ", length:paddinglen ) + sep + value + '\n';

    if( valuelen + maxlen > fulllen )
      fulllen = maxlen + valuelen;
  }

  if( strlen( report ) ) {
    if( hascolumnheader ) {

      reportheader = chomp( columnheader[0] ) + crap( data:" ", length:maxlen - columnheaderlen ) + sep + chomp( columnheader[1] ) + '\n';
      reportheaderlen = strlen( reportheader ) - 1; # nb: -1 for the '\n'

      if( fulllen + seplen < reportheaderlen )
        fulllen = reportheaderlen;
      else
        fulllen += seplen;

      reportheader += crap( data:"-", length:fulllen ) + '\n';
      report = reportheader + report;
    }
    return chomp( report );
  }
}

# @brief Creates an array of the commands 'ipconfig' and 'id' as the array key and the regex to match
#        against the response of these commands as the array value. The function will chose the
#        returned commands if the remote system is running on Windows, Linux or if the OS is unknown.
#
# @param _FCT_ANON_ARGS[0] Allows (optional) to pass either "windows" or "linux" as an anonymous function parameter
#                          to define directly which kind of files should be returned.
#
# @note Add a dependency to os_detection.nasl if you want to use this function. The VT calling this
#       function needs to also include os_func.inc (for os_host_runs());
#
# @return An array as described in the function summary.
#
function exploit_commands() {

  local_var res;

  if( _FCT_ANON_ARGS[0] ) {

    if( tolower( _FCT_ANON_ARGS[0] ) == "windows" ) {
      res = "yes";
    } else if( tolower( _FCT_ANON_ARGS[0] ) == "linux" ) {
      res = "no";
    }
  } else {
    res = os_host_runs( "windows" );
  }

  if( res == "yes" ) {
    return make_array( "Windows.IP..onfiguration", "ipconfig" );
  } else if( res == "no" ) {
    return make_array( "uid=[0-9]+.*gid=[0-9]+", "id" );
  }

  # unknown
  return make_array( "uid=[0-9]+.*gid=[0-9]+", "id",
                     "Windows.IP..onfiguration", "ipconfig" );
}

# @brief Gets the hostname of the target via get_host_name() and
#        if no IPv4/IPv6 address was returned by this function it
#        returns a list containing the parts of the target hostname.
#
#        For example a hostname of www.example.com returns a list containing
#        the following:
#        1 -> www
#        2 -> example
#        3 -> com
#        4 -> www.example
#        5 -> www.example.com
#        6 -> example.com
#        7 -> com.example
#        8 -> com.example.www
#
# @todo We currently can't catch a example.com from www.sub.example.com
#
# @return a list containing the parts of the target hostname, an empty list
#         if get_host_name() returned an IPv4/IPv6 address.
#
function create_hostname_parts_list() {

  local_var list, hnlist, hn, hnp, hnl, parts, i;

  list = make_list();

  # Available since GVM-10 / git commit 4ba1a59
  if( defined_func( "get_host_names" ) )
    hnlist = get_host_names();
  else
    hnlist = make_list( get_host_name() );

  foreach hn( hnlist ) {

    # nb: We don't want to add an IPv4/IPv6 address here...
    if( ":" >!< hn && ! ereg( string:hn, pattern:"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" ) ) {

      hnp = split( hn, sep:".", keep:FALSE );
      hnl = max_index( hnp );

      parts = "";
      for( i = 0; i < hnl; i++ ) {
        # each single entry on its own
        list = make_list( list, hnp[i] );
        # concatenate each entry with the previous one
        parts += "." + hnp[i];
        parts = ereg_replace( pattern:"^\.", string:parts, replace:'' );
        if( ! in_array( search:parts, array:list ) )
          list = make_list( list, parts );
      }

      parts = "";
      for( i = 1; i < hnl; i++ ) {
        # This is a special case to skip the first part like www from www.example.com
        parts += "." + hnp[i];
        parts = ereg_replace( pattern:"^\.", string:parts, replace:'' );
        if( ! in_array( search:parts, array:list ) )
          list = make_list( list, parts );
      }

      parts = "";
      for( i = hnl - 1; i >= 0; i-- ) {
        # concatenate each entry with the previous one
        parts += "." + hnp[i];
        parts = ereg_replace( pattern:"^\.", string:parts, replace:'' );
        if( ! in_array( search:parts, array:list ) )
          list = make_list( list, parts );
      }
    }
  }
  return list;
}

# @brief Checks if the VT calling this function is executed on a Greenbone OS (GOS).
#
# @return TRUE if executed on a GOS, FALSE if not executed on a GOS and NULL if the function
#         vendor_version() needed for this check is missing (e.g. running a GOS/GVM/OpenVAS
#         installation not providing this function yet).
#
function executed_on_gos() {

  if( ! defined_func( "vendor_version" ) )
    return NULL;

  if( vendor_version() =~ "^Greenbone OS" )
    return TRUE;
  else
    return FALSE;
}

# @brief Tries to detect the local Greenbone OS (GOS) version of the VT calling this function.
#
# @return The version number as a string if executed on a GOS and it was possible to gather the
#         version, FALSE if not executed on a GOS and NULL if it was not possible to gather the
#         version.
#
function get_local_gos_version() {

  local_var result;

  if( isnull( executed_on_gos() ) ) {
    return NULL;
  } else if( ! executed_on_gos() ) {
    return FALSE;
  } else {
    # nb: No need to check if "vendor_version()" is "defined" or includes useful data as this is
    # already covered by the previous "executed_on_gos()" call...
    result = eregmatch( pattern:"Greenbone OS ([0-9.]+)", string:vendor_version() );
    if( result[1] )
      return result[1];
    else
      return NULL;
  }
  return NULL;
}

# @brief Returns an array containing various representations of a Vulnerability Test (VT) string which can
#        be used in VTs as e.g. a user name.
#
# @note The returned string depends on the platform (OpenVAS/GVM/GOS) the scanner is running at.
#
# @return An array containing various string representations of either "GBVT" or "OpenVASVT"
#         depending on the platform the scanner is running at. Currently the following array indices
#         are supported / available:
#
#         ret_array["default"]             = either "GBVT" or "OpenVASVT"
#         ret_array["default_rand"]        = "default" with random numbers appended
#         ret_array["default_hex"]         = "default" converted to a hex string
#         ret_array["default_rand_hex"]    = "default_rand" converted to a hex string
#         ret_array["default_ver_space"]   = "default" with the current library version appended and a space as a separator
#         ret_array["default_ver_dash"]    = "default" with the current library version appended and a dash as a separator
#         ret_array["default_dash"]        = "default" with a dash ("-"), e.g. "GB-VT" or "OpenVAS-VT"
#         ret_array["default_rand_dash"]   = "default" with a dash with random numbers appended
#
#         ret_array["ping_string"] = either "GBVT" or "OpenVASVT" in a form of e.g. "_GBVT1234_" filled up to 16 bytes of total length, for the use in the "-p" parameter of unixoide ping commands which allows a max. of 16 bytes in the passed string
#
#         ret_array["lowercase"]           = either "gbvt" or "openvasvt"
#         ret_array["lowercase_rand"]      = "lowercase" with random numbers appended
#         ret_array["lowercase_hex"]       = "lowercase" converted to a hex string
#         ret_array["lowercase_rand_hex"]  = "lowercase_rand" converted to a hex string
#         ret_array["lowercase_ver_space"] = "lowercase" with the current library version appended and a space as a separator
#         ret_array["lowercase_ver_dash"]  = "lowercase" with the current library version appended and a dash as a separator
#         ret_array["lowercase_dash"]      = "lowercase" with a dash ("-"), e.g. "GB-VT" or "OpenVAS-VT"
#         ret_array["lowercase_rand_dash"] = "lowercase" with a dash with random numbers appended
#
#         ret_array["uppercase"]           = either "GBVT" or "OPENVASVT"
#         ret_array["uppercase_rand"]      = "uppercase" with random numbers appended
#         ret_array["uppercase_hex"]       = "uppercase" converted to a hex string
#         ret_array["uppercase_rand_hex"]  = "uppercase_rand" converted to a hex string
#         ret_array["uppercase_ver_space"] = "uppercase" with the current library version appended and a space as a separator
#         ret_array["uppercase_ver_dash"]  = "uppercase" with the current library version appended and a dash as a separator
#         ret_array["uppercase_dash"]      = "uppercase" with a dash ("-"), e.g. "GB-VT" or "OpenVAS-VT"
#         ret_array["uppercase_rand_dash"] = "uppercase" with a dash with random numbers appended
#
function get_vt_strings() {

  local_var ret_array, vt_string, vt_string_dash, version, vt_string_lo, vt_string_up, vt_string_dash_lo, vt_string_dash_up, rand_numbers;

  ret_array = make_array();

  if( executed_on_gos() ) {
    vt_string = "GBVT";
    vt_string_dash = "GB-VT";
  } else {
    vt_string = "OpenVASVT";
    vt_string_dash = "OpenVAS-VT";
  }

  if( OPENVAS_VERSION )
    version = OPENVAS_VERSION;
  else
    version = "1.0"; # nb: Just as a fallback if OPENVAS_VERSION isn't defined somehow.

  vt_string_lo = tolower( vt_string );
  vt_string_up = toupper( vt_string );
  vt_string_dash_lo = tolower( vt_string_dash );
  vt_string_dash_up = toupper( vt_string_dash );
  rand_numbers = string( rand() ); # nb: Returns an integer with a length between 9 and 10, converting it to string first

  ret_array["default"] = vt_string;
  ret_array["default_rand"] = vt_string + rand_numbers;
  ret_array["default_hex"] = hexstr( vt_string );
  ret_array["default_rand_hex"] = hexstr( vt_string + rand_numbers );
  ret_array["default_ver_space"] = vt_string + " " + version;
  ret_array["default_ver_dash"] = vt_string + "-" + version;
  ret_array["default_dash"] = vt_string_dash;
  ret_array["default_rand_dash"] = vt_string_dash + rand_numbers;

   # nb: e.g. for the use in the "-p" parameter of unixoide ping commands which allows a max. of 16 bytes in the passed string
  ret_array["ping_string"] = "_" + vt_string + substr( rand_numbers, 0, 16 - strlen( vt_string ) - 3 ) + "_";

  ret_array["lowercase"] = vt_string_lo;
  ret_array["lowercase_rand"] = vt_string_lo + rand_numbers;
  ret_array["lowercase_hex"] = hexstr( vt_string_lo );
  ret_array["lowercase_rand_hex"] = hexstr( vt_string_lo + rand_numbers );
  ret_array["lowercase_ver_space"] = vt_string_lo + " " + version;
  ret_array["lowercase_ver_dash"] = vt_string_lo + "-" + version;
  ret_array["lowercase_dash"] = vt_string_dash_lo;
  ret_array["lowercase_rand_dash"] = vt_string_dash_lo + rand_numbers;

  ret_array["uppercase"] = vt_string_up;
  ret_array["uppercase_rand"] = vt_string_up + rand_numbers;
  ret_array["uppercase_hex"] = hexstr( vt_string_up );
  ret_array["uppercase_rand_hex"] = hexstr( vt_string_up + rand_numbers );
  ret_array["uppercase_ver_space"] = vt_string_up + " " + version;
  ret_array["uppercase_ver_dash"] = vt_string_up + "-" + version;
  ret_array["uppercase_dash"] = vt_string_dash_up;
  ret_array["uppercase_rand_dash"] = vt_string_dash_up + rand_numbers;

  return ret_array;
}

# @brief Returns a (pseudo-)random integer based on range passed in the function parameters. If no
#        parameters got passed the range of the generated integer is between 0 and 2^31 by default.
#
# @note Internally the function is calling @ref rand provided by the scanner which in turn is
#       calling @ref lrand48 of stdlib.
#
# @param min The lower limit of the returned integer. Needs to be < max and >= 0.
# @param max The upper limit of the returned integer. Needs to be > min and >= 0.
#
# @return A (pseudo-)random integer based on the passed function parameters if wrong function
#         parameters got passed.
#
function rand_int_range( min, max ) {

  local_var min, max;
  local_var ret, type_min, type_max;

  # nb: Just the default of rand() in this case...
  if( isnull( min ) && isnull( max ) ) {
    ret = rand();
    return ret;
  }

  if( ! isnull( min ) ) {
    type_min = typeof( min );
    if( type_min != "int" ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#rand_int_range: Wrong type '" + type_min + "' (Expected: int) passed to the 'min' parameter. Returning NULL." );
      return NULL;
    }
  }

  if( ! isnull( max ) ) {
    type_max = typeof( max );
    if( type_max != "int" ) {
      set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#rand_int_range: Wrong type '" + type_max + "' (Expected: int) passed to the 'max' parameter. Returning NULL." );
      return NULL;
    }
  }

  if( ! isnull( max ) && ! isnull( min ) && max <= min ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#rand_int_range: Value '" + max + "' of 'max' parameter <= value '" + min + "' of 'min' parameter. Returning NULL." );
    return NULL;
  }

  if( ! min && max <= 0 ) {
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#rand_int_range: 'min' parameter not given / NULL but 'max' parameter <= 0/NULL'. Returning NULL." );
    return NULL;
  }

  if( min && max )
    ret = ( ( rand() % ( max - min + 1 ) ) + min );
  else if( ! min && max )
    ret = ( rand() % ( max + 1 ) );
  else
    ret = ( ( rand() % ( 2147483648 - min + 1 ) ) + min );

  return ret;
}
