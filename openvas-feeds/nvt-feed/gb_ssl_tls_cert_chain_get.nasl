# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105887");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2016-09-13 13:44:08 +0200 (Tue, 13 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSL/TLS: Get Certificate Chain");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_ssl_tls_version_get.nasl", "gb_ssl_tls_sni_supported.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"Gets the server certificate and all certificates in the chain
  from a remote SSL/TLS server and stores the info in the internal knowledge base.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("mysql.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("ssl_funcs.inc");
include("byte_func.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

if( ! version = get_supported_tls_version( port:port ) )
  exit( 0 );

if( ! soc = open_ssl_socket( port:port ) )
  exit( 0 );

if( get_kb_item( "sni/" + port + "/supported" ) )
  extensions = make_list( "sni" );

if( ! hello = ssl_hello( port:port, version:version, extensions:extensions ) )
  exit( 0 );

send( socket:soc, data:hello );

hello_done = FALSE;
cert_chain_extracted = FALSE;

while( ! hello_done ) {

  data = ssl_recv( socket:soc );
  if( ! data ) {
    close( soc );
    exit( 0 );
  }

  c = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_CERTIFICATE ) );

  server_cert = TRUE;

  if( c ) {
    foreach f( c["cert_list"] ) {
      if( ! certobj = cert_open( f ) ) # nb: is it a valid cert?
        continue;

      cert_close( certobj );

      if( server_cert ) {
        server_cert = FALSE;
        cert_chain_extracted = TRUE;
        set_kb_item( name:"ssl_tls/cert_chain/" + port + "/certs/server_cert", value:base64( str:f ) );
        continue;
      }

      cert_chain_extracted = TRUE;
      set_kb_item( name:"ssl_tls/cert_chain/" + port + "/certs/chain", value:base64( str:f ) );
    }
  }

  hd = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE, "content_typ", SSLv3_ALERT ) );
  if( hd ) {
    close( soc );
    hello_done = TRUE;
  }
}

if( cert_chain_extracted ) {
  set_kb_item( name:"ssl_tls/cert_chain/extracted", value:TRUE );
  set_kb_item( name:"ssl_tls/cert_chain/" + port + "/extracted", value:TRUE );
}

exit( 0 );
