# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105884");
  script_version("2024-09-27T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-27 05:05:23 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"creation_date", value:"2016-09-01 16:56:11 +0200 (Thu, 01 Sep 2016)");
  script_name("SSL/TLS: SNI Support Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_ssl_tls_version_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"This script test for SSL/TLS SNI support.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("mysql.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("ssl_funcs.inc");
include("byte_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

if( get_host_name() == get_host_ip() )
  exit( 0 );

if( ! version = get_supported_tls_version( port:port, min:TLS_10 ) )
  exit( 0 );

if( ! hello = ssl_hello( port:port, version:version, extensions:make_list( "sni" ) ) )
  exit( 0 );

if( ! soc = open_ssl_socket( port:port ) )
  exit( 0 );

send( socket:soc, data:hello );

hello_done = FALSE;
sni_supported = TRUE;

while( ! hello_done ) {

  if( ! data = ssl_recv( socket:soc ) ) {
    close( soc );
    exit( 0 );
  }

  ret = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO ) );
  if( ret ) {
    if( isnull( ret["extension_sni"] ) )
      sni_supported = FALSE;
  }

  ret = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE, "content_typ", SSLv3_ALERT ) );
  if( ret ) {
    if( ret["content_typ"] == SSLv3_ALERT && ret["description"] == SSLv3_ALERT_UNRECOGNIZED_NAME )
      sni_supported = FALSE;

    hello_done = TRUE;
    break;
  }
}

close( soc );

if( ! hello_done )
  exit( 0 );

if( sni_supported ) {

  if( service_verify( port:port, proto:"www" ) ) {

    # nb: Don't use http_get_cache as this might save the 400 error below into the cache.
    req = http_get( item:"/", port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( buf =~ "^HTTP/1\.[01] 400" || buf =~ "^HTTP/1\.[01] 5[0-9][0-9]" ) {

      replace_kb_item( name:"Host/SNI/" + port + "/force_disable", value:1 ); # on error disable SNI and try again

      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
      if( buf !~ "^HTTP/1\.[01] [2-3][0-9][0-9]" ) {
        replace_kb_item( name:"Host/SNI/" + port + "/force_disable", value:"0" ); # still an error. reactivate SNI
        set_kb_item( name:"sni/" + port + "/supported", value:TRUE );
      }
    } else {
      set_kb_item( name:"sni/" + port + "/supported", value:TRUE );
    }
  } else {
    set_kb_item( name:"sni/" + port + "/supported", value:TRUE );
  }
} else {
  replace_kb_item( name:"Host/SNI/" + port + "/force_disable", value:1 );
}

exit( 0 );
