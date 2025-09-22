# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105534");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-02-10 12:03:48 +0100 (Wed, 10 Feb 2016)");

  script_name("Cisco Application Policy Infrastructure Controller Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Cisco Application Policy Infrastructure
  Controller.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

buf = http_get_cache( port:port, item:"/" );

if( "<title>APIC</title>" >!< buf ) exit( 0 );

url = "/insieme/stromboli/meta/Version.js";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "insieme.stromboli.meta.Version" >!< buf || "versionString:" >!< buf ) exit( 0 );

set_kb_item( name:"cisco/application_policy_infrastructure_controller/installed", value:TRUE );

cpe = "cpe:/a:cisco:application_policy_infrastructure_controller";

version = eregmatch( pattern:"versionString: '([^']+)'", string:buf ); # for example 1.1(4e), 1.2(0.286), 1.2(1i), 1.1(2h), ...
if( ! isnull( version[1] ) ) {
  vers = version[1];
  cpe += ":" + vers;
  set_kb_item( name:"cisco/application_policy_infrastructure_controller/version", value:vers );
}

register_product( cpe:cpe, location:"/", port:port, service:"www" );

log_message( data:build_detection_report( app:"Cisco Application Policy Infrastructure Controller",
                                          version:vers,
                                          install:"/",
                                          cpe:cpe,
                                          concluded:version[0],
                                          concludedUrl:url ),
             port:port );

exit( 0 );
