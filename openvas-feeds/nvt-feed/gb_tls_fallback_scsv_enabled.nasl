# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105483");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2015-12-11 15:21:49 +0100 (Fri, 11 Dec 2015)");
  script_name("SSL/TLS: TLS_FALLBACK_SCSV Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_ssl_tls_version_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"This script reports if TLS_FALLBACK_SCSV is enabled or not.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("mysql.inc");
include("ssl_funcs.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("byte_func.inc");

function _check_tls_fallback_scsv( port, ssl_ver ) {

  local_var hello, soc, hdr, len, pay, len1, next, mult, hello_done, port, ssl_ver;

  hello = ssl_hello( port:port, version:ssl_ver, add_tls_fallback_scsv:TRUE );

  soc = open_ssl_socket( port:port );
  if( ! soc )
    return FALSE;

  send( socket:soc, data:hello );

  while ( ! hello_done ) {

    hdr = recv( socket:soc, length:5, timeout:5 );

    if( ! hdr || strlen( hdr ) != 5 ) {
      close( soc );
      return FALSE;
    }

    len = getword( blob:hdr, pos:3 );
    pay = recv( socket:soc, length:len, timeout:5 );

    if( ! pay ) {
      close( soc );
      return FALSE;
    }

    if( ord( hdr[0] ) == SSLv3_ALERT ) {
      if( strlen( pay ) < 2 ) {
        close( soc );
        return FALSE;
      }

      # If TLS_FALLBACK_SCSV appears in ClientHello.cipher_suites and the
      # highest protocol version supported by the server is higher than
      # the version indicated in ClientHello.client_version, the server
      # MUST respond with an inappropriate_fallback alert.
      if( ord( pay[ 1 ] ) == SSLv3_ALERT_INAPPROPRIATE_FALLBACK ) {
        close( soc );
        return TRUE;
      }
    }

    if( ord( pay[0] ) == 13 && ord( hdr[0] ) == 22 ) {
      len1 = getword( blob:pay, pos:2 );
      next = substr( pay, len1 + 4 );

      if( next && ord( next[0] ) == 14 ) {
        hello_done = TRUE;
        close( soc );
        return FALSE;
      }
    }

    if( ( strlen( pay ) - 4 ) > 0 )
      mult = substr( pay, ( strlen( pay ) - 4 ), strlen( pay ) );

    if( ( ord( pay[0] ) == 14 || ( mult && ord( mult[0] ) == 14 ) ) && ord( hdr[0] ) == 22 ) {
      hello_done = TRUE;
      close( soc );
      return FALSE;
    }
  }

  close( soc );
  return FALSE;
}

if( ! port = tls_ssl_get_port() )
  exit( 0 );

# TODO: Also check TLS_FALLBACK_SCSV for all other protocols
ssl_ver = SSL_v3;

if( _check_tls_fallback_scsv( port:port, ssl_ver:ssl_ver ) ) {
  report = 'It was determined that the remote TLSv1.0+ service supports the TLS_FALLBACK_SCSV and is therefore not affected by downgrading attacks like the POODLE vulnerability.';
  set_kb_item( name:"tls_fallback_scsv_supported/" + port, value:TRUE );
  #log_message( port:port, data:report );
  exit( 99 );
}

report = 'It was determined that the remote TLSv1.0+ service does not support the TLS_FALLBACK_SCSV and might be affected by downgrading attacks like the POODLE vulnerability.';
#log_message( port:port, data:report );
exit( 0 );
