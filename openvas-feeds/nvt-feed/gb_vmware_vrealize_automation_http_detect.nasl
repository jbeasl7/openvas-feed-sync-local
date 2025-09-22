# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105863");
  script_version("2025-09-09T14:09:45+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-08-11 17:10:02 +0200 (Thu, 11 Aug 2016)");
  script_name("VMware vRealize Automation Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of VMware vRealize Automation.");

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

if( "title>VMware vRealize Automation" >!< buf || ">VMware<" >!< buf || "vRealize Automation console" >!< buf )
  exit( 0 );

set_kb_item( name:"vmware/vrealize/automation/detected", value:TRUE );
set_kb_item( name:"vmware/vrealize/automation/http/detected", value:TRUE );

vers = "unknown";
rep_vers = vers;

cpe = "cpe:/a:vmware:vrealize_automation";

# VMware vRealize Automation Appliance 6.2.1.0-2553372<br/>
v_b = eregmatch( pattern:"VMware vRealize Automation( Appliance)? ([0-9.]+)-([0-9]+)", string:buf );

# VMware vRealize Automation Appliance version 7.0.1.100 (build 3621464)<br/>
if( isnull( v_b ) )
  v_b = eregmatch( pattern:"VMware vRealize Automation( Appliance)? version ([0-9.]+) \(build ([0-9]+)\)", string:buf );

if( ! isnull( v_b[2] ) ) {
  vers = v_b[2];
  rep_vers = vers;
  set_kb_item( name:"vmware/vrealize/automation/version", value:vers );
  cpe += ":" + vers;
}

if( ! isnull( v_b[3] ) ) {
  build = v_b[3];
  rep_vers += " (Build: " + build + ")";
  set_kb_item( name:"vmware/vrealize/automation/build", value:build );
}

register_product( cpe:cpe, location:"/", port:port, service:"www" );

report = build_detection_report( app:"VMware vRealize Automation", version:rep_vers, install:"/", cpe:cpe, concluded:v_b[0] );
log_message( port:port, data:report );

exit( 0 );
