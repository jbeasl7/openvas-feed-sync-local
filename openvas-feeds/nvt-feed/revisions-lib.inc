# SPDX-FileCopyrightText: 2007 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Checks if a passed char is a numerical / digit one.
#
# @brief a The char to check.
#
# @return TRUE if the passed char is a numerical / digit one, FALSE otherwise.
#
function isdigit( a ) {

  local_var a;

  if( ord( a ) >= ord( '0' ) && ord( a ) <= ord( '9' ) )
    return TRUE;
  else
    return FALSE;
}

# @brief Function that can be used to compare two software package version
#        strings. Version string comparison operates on a slightly different
#        set or ordering rules: Instead of comparing character by character
#        exclusively throughout the whole string, we instead compare character
#        by character until we run into a numeric, at which point we extract
#        the entire numeric, and do a numeric comparison. That allows things
#        like v10.1 to be greater than v9, whereas any other string comparison
#        would result in v9 being larger, because '9' is larger than '1'.
#        Typical strcmp return values (0=; -1<; 1>;)
#
# @param a The base version to compare.
# @param b The version to compare against.
#
# @return 0 If the versions passed via the a and b parameter are the same, -1 if b > a and 1 if b < a.
#
function revcomp( a, b ) {

  local_var a, b;
  local_var done, work_a, work_b, rc, lena, lenb, i, subm_a, subm_b, sub_a, sub_b;

  if( ! a )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#a#-#revcomp" );
  if( ! b )
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#b#-#revcomp" );

  if( a =~ "^\s+" || a =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#revcomp: Trailing / leading space passed to 'a' parameter which might show an unexpected behavior." );

  if( b =~ "^\s+" || b =~ "\s+$" )
    set_kb_item( name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#revcomp: Trailing / leading space passed to 'b' parameter which might show an unexpected behavior." );

  if( a == b )
    return( 0 );

  done = 0;
  work_a = a;
  work_b = b;
  rc = 0;

  while( ! done ) {

    lena = strlen( work_a );
    lenb = strlen( work_b );

    if( lena == 0 ) {
      if( lenb > 0 ) {
        rc = -1;
        break;
      }
      if( lenb == 0 ) {
        break;
      }
    }
    for( i = 0; i < lena; i++ ) {
      if( i >= lenb ) {
        done = 1;
        rc = 1;
        break;
      }
      if( isdigit( a:work_a[i] ) && isdigit( a:work_b[i] ) ) {

        subm_a = eregmatch( pattern:"([0-9]+)", string:substr( work_a, i ) );
        subm_b = eregmatch( pattern:"([0-9]+)", string:substr( work_b, i ) );
        sub_a  = subm_a[1];
        sub_b  = subm_b[1];
        work_a = substr( work_a, i + strlen( sub_a ) );
        work_b = substr( work_b, i + strlen( sub_b ) );

        if( int( sub_a ) > int( sub_b ) ) {
          done = 1;
          rc = 1;
          break;
        }
        if( int( sub_a ) < int( sub_b ) ) {
          done = 1;
          rc = -1;
          break;
        }
        if( int( sub_a ) == int( sub_b ) ) {
          # If we have an empty string here, we're done.
          if( strlen( work_a ) == 0 || strlen( work_b ) == 0 ) {
            if( strlen( work_a ) == 0 ) {
              if( strlen( work_b ) == 0 ) {
                done = 1;
                break;
              } else {
                done = 1;
                rc = -1;
                break;
              }
            } else {
              done = 1;
              rc = 1;
              break;
            }
          }
          if( work_a[0] == '.' && work_b[0] != '.' ) {
            done = 1;
            rc = 1;
            break;
          }
          if( work_a[0] != '.' && work_b[0] == '.' ) {
            done = 1;
            rc = -1;
            break;
          }
          # Both must be dots. Allow the check to proceed normally.
          break;
        }
      }
      if( ord( work_a[i] ) < ord( work_b[i] ) ) {
        done = 1;
        rc = -1;
        break;
      }
      if( ord( work_a[i] ) > ord( work_b[i] ) ) {
        done = 1;
        rc = 1;
        break;
      }
      if( i == lena - 1 && lenb > lena ) {
        done = 1;
        rc = -1;
        break;
      }
    }
  }
  return( rc );
}
