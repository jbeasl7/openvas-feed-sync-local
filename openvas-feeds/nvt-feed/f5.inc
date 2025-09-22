# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# See https://my.f5.com/manage/s/article/K51812227 for F5 advisory versioning.

# Global vars to avoid that we're repeatedly asking redis for something we already know.
global_var __f5_valid_products, __f5_kb_hotfix;

# @brief Return the installed hotfix from the KB
#
# @return The installed hotfix from KB entry "f5/big_ip/hotfix" or "0" if no hotfix is installed.
#
function f5_hotfix_from_kb() {

  local_var hotfix;

  # Used to not query redis with the get_kb_item below
  # to save some requests.
  if( ! isnull( __f5_kb_hotfix ) ) {
    return __f5_kb_hotfix;
  } else {
    if( ! hotfix = get_kb_item( "f5/big_ip/hotfix" ) ) {
      hotfix = int( 0 );
    } else {
      hotfix = int( hotfix );
      __f5_kb_hotfix = hotfix;
    }
  }

  return hotfix;
}

# @brief Return all valid F5 products we currently cover.
#
# @return A list of currently supported F5 products
#
function f5_valid_products() {

  local_var valid_products;

  if( ! isnull( __f5_valid_products ) ) {
    return __f5_valid_products;
  } else {
    # nb:
    # - BIG-IP GTM name has changed to BIG-IP DNS according to https://my.f5.com/manage/s/article/K17329
    # - Overview on the modules is available at https://my.f5.com/manage/s/article/K2200
    # - LC = Short name for "Link Controller"
    # - AVR = Short name for "Analytics"
    # - PSM, WOM, and WAM = Aged modules which seems to be no longer supported
    valid_products = make_list( "LTM", "AAM", "AFM", "APM", "ASM", "GTM", "PEM", "PSM", "WOM", "AVR", "WAM", "LC", "DNS" );
    __f5_valid_products = valid_products;
    return valid_products;
  }
}

# @brief Checks if an active module and its version is vulnerable
#
# @param ca An array of an active module including the affected and unaffected versions.
#           For example: ca['ASM'] = make_array('affected',   '15.0.1;',
#                                               'unaffected', '15.1.0;15.0.1.4;');
# @param version The installed version to check against
#
# @return A generated report built with f5_build_report() in case of the version is in the affected range and
#         not in the unaffected versions or NULL if the version is either not in the affected range or equal or
#         higher than the unaffected version in the major release.
#
function f5_is_vulnerable( ca, version )
{
  local_var ca, version;
  local_var active_modules, is_vulnerable, _product, av_array, affected, unaffected, af, _a, affected_modules, unaffected_modules;

  if( ! is_array( ca ) )
    return;

  if( ! version )
    return;

  if( ! active_modules = get_kb_item( "f5/big_ip/active_modules" ) )
    return;

  is_vulnerable = FALSE;

  foreach _product( keys( ca ) )
  {
    if( ! in_array( search:_product, array:f5_valid_products() ) )
      continue;

    if( _product >!< active_modules )
      continue;

    av_array = ca[ _product ];

    affected = av_array[ 'affected' ];
    unaffected = av_array[ 'unaffected' ];

    if( ! strlen( affected ) )
      return;

    if( strlen( unaffected ) )
    {
      if( f5_is_unaffected( version:version, unaffected:unaffected ) )
        return;
    }

    af = split( affected, sep:";", keep:FALSE );
    if( ! is_array( af ) )
      continue;

    foreach _a( af )
    {
      if( f5_check_version( a:_a, version:version ) )
      {
        affected_modules += '\t' + _product + ' (' + f5_clean_version( v:_a ) + ')\n';
        unaffected_modules += '\t' + _product + ': ' + f5_clean_version( v:unaffected ) + '\n';
        is_vulnerable = TRUE;
        break;
      }
    }
  }

  if( is_vulnerable )
    return f5_build_report( affected_modules:affected_modules,
                            unaffected_modules:unaffected_modules,
                            version:version );

  return;
}

# @brief Checks if the installed version is unaffected
#
# @param version    The installed version to check
#
# @param unaffected A semicolon (;) separated string of unaffected versions
#
# affected   -> 11.0.0-11.5.3
# unaffected -> 11.4.1_HF10
#
# @return TRUE if the installed version is greater or equal the unaffected versions NULL otherwise.
#
function f5_is_unaffected( version, unaffected )
{
  local_var version, unaffected;
  local_var ua, _uav, v_h, c_version, c_hotfix, both, first, last, first_hotfix, last_hotfix, major, pattern;

  if( ! version )
    return;

  if( ! unaffected )
    return;

  ua = split( unaffected, sep:";", keep:FALSE );
  if( ! is_array( ua ) )
    return;
  foreach _uav( ua )
  {
    if( "_HF" >< _uav && "-" >!< _uav )
    {
      v_h = eregmatch( pattern:'([0-9.]+)_HF([0-9]+)', string:_uav );

      c_version = v_h[1];
      c_hotfix  = v_h[2];

      if( isnull( c_version ) || isnull( c_hotfix ) )
        return;

      if( version == c_version )
      {
        if( f5_hotfix_from_kb() >= int( c_hotfix ) )
          return TRUE;
      }
    }
    else
    {
      if( "-" >< _uav )
      {
        both = split( _uav, sep:'-', keep:FALSE );
        if( isnull( both[0] ) || isnull( both[1] ) )
          return;

        first = both[0];
        last  = both[1];

        first_hotfix = int( 0 );
        last_hotfix  = int( 0 );

        if( "_HF" >< first )
        {
          v_h = eregmatch( pattern:'([0-9.]+)_HF([0-9]+)', string:first );
          if( ! is_array( v_h ) )
            return;

          first = v_h[1];
          first_hotfix = v_h[2];
        }

        if( "_HF" >< last )
        {
          v_h = eregmatch( pattern:'([0-9.]+)_HF([0-9]+)', string:last );
          if( ! is_array( v_h ) )
            return;

          last = v_h[1];
          last_hotfix = v_h[2];
        }

        first += '.' + first_hotfix;
        last  += '.' + last_hotfix;

        if( version_in_range( version:version + '.' + f5_hotfix_from_kb(), test_version:first, test_version2:last ) )
          return TRUE;
      }
      else
      {
        # Check if we test against the right major version so we don't falsely mark the version unaffected
        # if lower unaffected versions exist
        major = split( _uav, sep:".", keep:FALSE );
        pattern = "^" + major[0] + "\.";
        if( egrep( pattern:pattern, string:version ) &&
            version_is_greater_equal( version:version, test_version:_uav ) )
          return TRUE;
      }
    }
  }
  return;
}

# @brief Checks if the installed version/hotfix is in the vulnerable range
#
# @param a The affected version or version range
#
# @param version The installed version
#
# @return TRUE if the installed version is either in the affected range or equal to the affected version whereas
#         the affected range might be just the major version (see https://my.f5.com/manage/s/article/K51812227),
#         NULL otherwise.
#
function f5_check_version( a, version )
{
  local_var a, version;
  local_var v, c_version, hotfixes, low_hotfix, hi_hotfix, both, b, v_high, v_low, hi, low, fvh, first_vuln_hotfix, v_h, c_hotfix, first, last, pattern;

  # 11.5.1 HF4-HF8
  if( a =~ "[0-9.]+_HF([0-9]+)-HF([0-9]+)" )
  {
    v = eregmatch( pattern:'([0-9.]+)_HF', string:a );
    if( isnull( v[1] ) )
      return;

    c_version = v[1];

    hotfixes = eregmatch( pattern:'[0-9.]+_HF([0-9]+)-HF([0-9]+)', string:a );
    if( isnull( hotfixes[1] ) || isnull( hotfixes[2] ) )
      return;

    low_hotfix = hotfixes[1];
    hi_hotfix  = hotfixes[2];

    if( version == c_version )
    {
      if( f5_hotfix_from_kb() < int( low_hotfix ) )
        return;

      if( f5_hotfix_from_kb() <= int( hi_hotfix ) )
        return TRUE;

    }
    return;
  }

  if( "_HF" >< a )
  {
    if( "-" >< a )
    {
      both = split( a, sep:'-', keep:FALSE );
      if( isnull( both[1] ) )
        return;

      a = both[1];
      b = both[0];

      v_high = eregmatch( pattern:'([0-9.]+)(_HF)?', string:a );
      v_low = eregmatch( pattern:'([0-9.]+)(_HF)?', string:b );

      hi = v_high[1];
      low = v_low[1];

      #11.4.0 - 11.5.4 HF1
      if( hi != low )
      {
        if( version_in_range( version:version, test_version:low, test_version2:hi ) )
        {
          if( version == hi )
          {
            fvh = eregmatch( pattern:'([0-9.]+)_HF([0-9]+)', string:a );
            if( ! isnull( fvh[2] ) )
            {
              if( f5_hotfix_from_kb() > int( fvh[2] ) )
                return;
            }
          }

          if( version == low )
          {
            fvh = eregmatch( pattern:'([0-9.]+)_HF([0-9]+)', string:b );
            if( ! isnull( fvh[2] ) )
            {
              if( f5_hotfix_from_kb() < int( fvh[2] ) )
                return;
            }
          }
          return TRUE;
        }
      }

      if( "_HF" >< b )
      {
        fvh = eregmatch( pattern:'([0-9.]+)_HF([0-9]+)', string:b );
        if( ! isnull( fvh[2] ) )
          first_vuln_hotfix = fvh[2];
      }
    }

    v_h = eregmatch( pattern:'([0-9.]+)_HF([0-9]+)', string:a );

    c_version = v_h[1];
    c_hotfix  = v_h[2];

    if( isnull( c_version ) || isnull( c_hotfix ) )
      return;

    if( c_version == version )
    {
      # Versions known to be vulnerable: 11.5.1 HF6 - 11.5.1 HF10
      if( first_vuln_hotfix )
      {
        if( f5_hotfix_from_kb() < int( first_vuln_hotfix ) )
          return;
      }

      if( f5_hotfix_from_kb() <= int( c_hotfix ) )
        return TRUE;
    }
    return;
  }
  else
  {
    if( "-" >< a )
    {
      both = split( a, sep:'-', keep:FALSE );
      if( isnull( both[0] ) || isnull( both[1] ) )
        return;

      first = both[0];
      last  = both[1];

      if( version_in_range( version:version, test_version:first, test_version2:last ) )
        return TRUE;

      # To get a proper regex pattern replace "." with "\."
      last = ereg_replace( pattern:"\.", string:last, replace:"\." );
      pattern = "^" + last;
      if( egrep( pattern:pattern, string:version ) )
        return TRUE;
    }
    else
    {
      if( version == a )
        return TRUE;
    }
  }
  return;
}

# @brief Strip special characters from the version for reporting
#
# @param v The version string to clean up
#
# @return The cleaned up version
#
function f5_clean_version( v )
{
  local_var v, ret;

  ret = str_replace( string:v, find:';', replace:", " );
  ret = str_replace( string:ret, find:'_HF', replace:" HF" );
  ret = str_replace( string:ret, find:'-', replace:" - " );
  ret = ereg_replace( string:ret, pattern:', $', replace:"" );
  return ret;
}

# @brief Build a report for vulnerable version/hotfix
#
# @param affected_modules The affected modules/versions
#
# @param unaffected_modules The unaffected modules/versions
#
# @param version The installed version
#
# @return A report string including the installed version/hotfix and the affected and unaffected modules/versions
#
function f5_build_report( affected_modules, unaffected_modules, version )
{
  local_var affected_modules, unaffected_modules, version;
  local_var report, hotfix;

  report = 'Installed Version: ' + version + '\n';

  hotfix = f5_hotfix_from_kb();
  if( hotfix )
    report += 'Installed Hotfix: ' + hotfix;

  report += '\n\nAffected Modules:\n\n' + affected_modules + '\n';
  report += '\nUnaffected Modules:\n\n' + unaffected_modules + '\n';
  return report;
}
