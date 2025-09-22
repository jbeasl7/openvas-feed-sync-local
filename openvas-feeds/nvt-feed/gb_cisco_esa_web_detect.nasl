# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105314");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-06 11:43:00 +0200 (Mon, 06 Jul 2015)");
  script_name("Cisco Email Security Appliance Web Interface Detection");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Cisco Email Security Appliance");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:443 );

url = '/login?redirects=20';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf !~ "<title>\s*Cisco\s*Email Security (Virtual )?Appliance" ) exit( 0 );

set_kb_item( name:"cisco_esa/installed", value:TRUE );
cpe = 'cpe:/h:cisco:email_security_appliance';

if( "Set-Cookie" >< buf )
{
  cookie = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string:buf );
  if( ! isnull( cookie[1] ) ) set_kb_item( name:"cisco_esa/http/cookie", value:cookie[1] );
}

set_kb_item( name:"cisco_esa/http/port", value:port );

version = eregmatch( pattern:'text_login_version">Version: ([^<]+)</p>', string:buf );

if( isnull( version[1] ) )
  version = eregmatch( pattern:'/scfw/1y-([0-9.-]+)/yui/', string:buf );

if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
  set_kb_item( name:"cisco_esa/version/http", value:vers );
}

m = eregmatch( pattern:'text_login_model">Cisco ([^<]+)</p>', string:buf );
if( ! isnull( m[1] ) )
{
  model = m[1];
  set_kb_item( name:"cisco_esa/model/http", value:model );
  rep_model = ' (' + model + ')';
}

# TODO: Using register_product( cpe:cpe ); Might cause forking issues as gb_cisco_eam_version.nasl is also registering this product.

log_message( data: build_detection_report( app:"Cisco Email Security Appliance" + rep_model + ' Web Interface',
                                           version:vers,
                                           install:"/",
                                           cpe:cpe,
                                           concluded: version[0] ),
             port:port );
exit(0);

