# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Texts are kept so output of scripts doesn't change in a delta
strengthtext["strong"]  = "'Strong'";
strengthtext["medium"]  = "'Medium'";
strengthtext["weak"]    = "'Weak'";
strengthtext["null"]    = "'Null'";
strengthtext["anon"]    = "'Anonymous'";
strengthtext["nonweak"] = "'Non Weak'";

# From ssl_funcs.inc
global_var version_string, version_kb_string_mapping, SSL_v2, SSL_v3, TLS_10, TLS_11, TLS_12, TLS_13;

# From ssl_funcs.inc
version_kb_string_mapping[SSL_v2] = "sslv2";
version_kb_string_mapping[SSL_v3] = "sslv3";
version_kb_string_mapping[TLS_10] = "tlsv1";
version_kb_string_mapping[TLS_11] = "tlsv1_1";
version_kb_string_mapping[TLS_12] = "tlsv1_2";
version_kb_string_mapping[TLS_13] = "tlsv1_3";

# From ssl_funcs.inc
version_string[SSL_v2] = "SSLv2";
version_string[SSL_v3] = "SSLv3";
version_string[TLS_10] = "TLSv1.0";
version_string[TLS_11] = "TLSv1.1";
version_string[TLS_12] = "TLSv1.2";
version_string[TLS_13] = "TLSv1.3";

# @brief Inner iterator over the requested strength for a given port and SSL/TLS protocol version to
#        create a cipher report
#
# @param port     The (mandatory) SSL/TLS port
# @param version  A (mandatory) valid SSL/TLS protocol version (as a constant like TLS_10 from
#                 ssl_func.inc)
# @param strength A (mandatory) string containing one of: "strong", "medium", "weak", "null", "anon"
# @param negative If (optionally) set to TRUE prints the output if no match for this version/level
#                 was found
#
# @return A report of the found ciphers as a string or NULL if none found or not all mandatory
#         parameters are given
#
function print_cipherlist( port, version, strength, negative ) {

  local_var port, version, strength, negative;
  local_var report, cipherlistname, cipherlist, cipher;

  if( isnull( port ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#print_cipherlist" );
    return NULL;
  }

  if( isnull( version ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#print_cipherlist" );
    return NULL;
  }

  if( isnull( strength ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#strength#-#print_cipherlist" );
    return NULL;
  }

  report = NULL;

  # nb: No cipher enumeration for SSLv2 is done (in gb_ssl_tls_ciphers_gathering.nasl) because this doesn't
  # make much sense these days:
  # The protocol itself is long deprecated, has so many flaws and is already reported separately
  # (in 2015/sw_sslv2_v3_detect.nasl) as deprecated with a severity accordingly.
  if( version == SSL_v2 )
    return report;

  cipherlistname = "ssl_tls/ciphers/" + version_kb_string_mapping[version] + "/" + port + "/" +
                   strength + "_ciphers";
  cipherlist = get_kb_list( cipherlistname );
  if( ! isnull( cipherlist ) ) {
    report += strengthtext[strength] + ' cipher suites accepted by this service via the ' +
              version_string[version] + ' protocol:\n\n';

    # Sort to not report changes on delta reports if just the order is different
    cipherlist = sort( cipherlist );
    foreach cipher( cipherlist )
      report += cipher + '\n';
    report += '\n';
  } else {
    if( negative ) {
      report += 'No ' + strengthtext[strength] + ' cipher suites accepted by this service via the ' +
                version_string[version] + ' protocol.\n\n';
    }
  }

  return report;
}

# @brief Middle iterator over the requested strength(s) for a given port and SSL/TLS protocol
#        version to create a cipher report
#
# @param port      The (mandatory) SSL/TLS port
# @param version   A (mandatory) valid SSL/TLS protocol version (as a constant like TLS_10 from
#                  ssl_func.inc)
# @param strengths A (mandatory) string with one or more (comma separated) of:
#                  "strong", "medium", "weak", "null", "anon"
# @param negative  If (optionally) set to TRUE prints the output if no match for this version/level
#                  was found
#
# @return A report of the found ciphers as a string or NULL if none found or not all mandatory
#         parameters are given
#
function print_cipherlist_version( port, version, strengths, negative ) {

  local_var port, version, strengths, negative;
  local_var report;

  if( isnull( port ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#print_cipherlist_version" );
    return NULL;
  }

  if( isnull( version ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#version#-#print_cipherlist_version" );
    return NULL;
  }

  if( isnull( strengths ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#strengths#-#print_cipherlist_version" );
    return NULL;
  }

  report = NULL;

  # nb: No cipher enumeration for SSLv2 is done (in gb_ssl_tls_ciphers_gathering.nasl) because this doesn't
  # make much sense these days:
  # The protocol itself is long deprecated, has so many flaws and is already reported separately
  # (in 2015/sw_sslv2_v3_detect.nasl) as deprecated with a severity accordingly.
  if( version == SSL_v2 )
    return report;

  # nb: since arrays can be reordered, this is unrolled
  if( "strong" >< strengths )
    report += print_cipherlist( port:port, version:version, strength:"strong", negative:negative );

  if( "medium" >< strengths )
    report += print_cipherlist( port:port, version:version, strength:"medium", negative:negative );

  if( "weak" >< strengths )
    report += print_cipherlist( port:port, version:version, strength:"weak", negative:negative );

  if( "null" >< strengths )
    report += print_cipherlist( port:port, version:version, strength:"null", negative:negative );

  if( "anon" >< strengths )
    report += print_cipherlist( port:port, version:version, strength:"anon", negative:negative );

  if( "nonweak" >< strengths )
    report += print_cipherlist( port:port, version:version, strength:"nonweak", negative:negative );

  return report;
}

# @brief Outer iterator over the requested strength(s) for a given port to create a cipher report
#
# @param port      The (mandatory) SSL/TLS port
# @param strengths A (mandatory) string with one or more (comma separated) of:
#                  "strong", "medium", "weak", "null", "anon"
# @param negative  If (optionally) set to TRUE prints the output if no match for this version/level
#                  was found
#
# @return A report of the found ciphers as a string or NULL if none found or not all mandatory
#         parameters are given
#
function print_cipherlists( port, strengths, negative ) {

  local_var port, strengths, negative;
  local_var report, sup_ssl;

  if( isnull( port ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#print_cipherlists" );
    return NULL;
  }

  if( isnull( strengths ) ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#strengths#-#print_cipherlists" );
    return NULL;
  }

  report = NULL;

  if( ! sup_ssl = get_kb_item( "tls/supported/" + port ) )
    return report;

  # nb: No cipher enumeration for SSLv2 is done (in gb_ssl_tls_ciphers_gathering.nasl) because this doesn't
  # make much sense these days:
  # The protocol itself is long deprecated, has so many flaws and is already reported separately
  # (in 2015/sw_sslv2_v3_detect.nasl) as deprecated with a severity accordingly.

  # nb: since arrays can be reordered, this is unrolled
  if( "SSLv3" >< sup_ssl )
    report += print_cipherlist_version( port:port, version:SSL_v3, strengths:strengths, negative:negative );

  if( "TLSv1.0" >< sup_ssl )
    report += print_cipherlist_version( port:port, version:TLS_10, strengths:strengths, negative:negative );

  if( "TLSv1.1" >< sup_ssl )
    report += print_cipherlist_version( port:port, version:TLS_11, strengths:strengths, negative:negative );

  if( "TLSv1.2" >< sup_ssl )
    report += print_cipherlist_version( port:port, version:TLS_12, strengths:strengths, negative:negative );

  if( "TLSv1.3" >< sup_ssl )
    report += print_cipherlist_version( port:port, version:TLS_13, strengths:strengths, negative:negative );

  return report;
}
