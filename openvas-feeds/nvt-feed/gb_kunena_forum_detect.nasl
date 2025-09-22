# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108105");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-03-23 09:57:33 +0100 (Thu, 23 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Kunena Forum Extension for Joomla Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Detection of the Kunena forum extension for Joomla.

  The script sends a HTTP request to the server and attempts to extract the version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

install = dir;
if( dir == "/" )
  dir = "";

url = dir + '/plugins/kunena/kunena/kunena.xml';
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

urls = dir + '/plugins/system/kunena/kunena.xml';
req2 = http_get( item:urls, port:port );
res2 = http_keepalive_send_recv( port:port, data:req );

if( "<name>plg_kunena_kunena</name>" >< res || "<name>plg_kunena_kunena</name>" >< res2 ) {

  version = "unknown";

  ver = eregmatch( pattern:"<version>([0-9.]+)</version>", string:res );
  if( ! isnull( ver[1] ) ) {
    version = ver[1];
    conclUrl = http_report_vuln_url( url:url, port:port, url_only:TRUE );
  } else {
    ver = eregmatch( pattern:"<version>([0-9.]+)</version>", string:res2 );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      conclUrl = http_report_vuln_url( url:url, port:port, url_only:TRUE );
    }
  }

  set_kb_item( name:"www/" + port + "/kunena_forum", value:version );
  set_kb_item( name:"kunena_forum/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:kunena:kunena:");
  if( ! cpe )
    cpe = "cpe:/a:kunena:kunena";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Kunena Forum Extension",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:ver[0] ),
                                            port:port );
}

exit( 0 );
