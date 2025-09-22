# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105102");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-11-03 13:25:47 +0100 (Mon, 03 Nov 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Scalix Detection (HTTP, SMTP, IMAP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "smtpserver_detect.nasl", "check_smtp_helo.nasl", "imap4_banner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, "Services/smtp", 25, 465, 587, "Services/imap", 143, 993);

  script_tag(name:"summary", value:"The script sends a connection request to the server and
  attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("smtp_func.inc");
include("imap_func.inc");
include("misc_func.inc");

function _report( port, version, location, concluded, service )
{
  if( ! version || version == '' ) return;

  if( ! location ) location = port + '/tcp';

  set_kb_item( name:'scalix/' + port + '/version', value:version );
  set_kb_item( name:"scalix/installed",value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:scalix:scalix:" );
  if( ! cpe )
    cpe = "cpe:/a:scalix:scalix";

  register_product( cpe:cpe, location:location, port:port, service:service );

  log_message( data:build_detection_report( app:"Scalix",
                                            version:version,
                                            install:location,
                                            cpe:cpe,
                                            concluded:concluded ),
               port:port );
  exit( 0 );
}

ports = http_get_ports(default_port_list:make_list(80));
foreach port( ports )
{

  if(http_is_cgi_scan_disabled())
    break;

  url = "/webmail/";
  buf = http_get_cache( item:url, port:port );

  if( buf && "<title>Login to Scalix Web Access" >< buf )
  {
    vers = 'unknown';
    buf_sp = split( buf, keep:FALSE );

    for( i=0; i< max_index( buf_sp ); i++ )
    {
      if( "color:#666666;font-size:9px" >< buf_sp[ i ] )
      {
        if( version = eregmatch( pattern:"([0-9.]+)" , string:buf_sp[ i + 1 ] ) )
        {
          _report( port:port, version:version[1], location:"/webmail/", concluded:version[0], service:"www" );
          break;
        }
      }
    }
  }
}

ports = smtp_get_ports();
foreach port( ports )
{
  banner = smtp_get_banner( port:port );
  if( banner && "ESMTP Scalix SMTP" >< banner )
  {
    if( version = eregmatch( pattern:"ESMTP Scalix SMTP Relay ([0-9.]+);" , string:banner ) )
    {
      _report( port:port, version:version[1], concluded:'SMTP banner', service:"smtp" );
    }
  }
}

ports = imap_get_ports();
foreach port( ports )
{
  banner = imap_get_banner( port:port );
  if( banner && "Scalix IMAP server" >< banner )
  {
    if( version = eregmatch( pattern:"Scalix IMAP server ([0-9.]+)" , string:banner ) )
    {
      _report( port:port, version:version[1], concluded:'IMAP banner', service:"imap" );
    }
  }
}

exit( 0 );
