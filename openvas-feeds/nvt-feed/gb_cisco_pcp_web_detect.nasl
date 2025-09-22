# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105548");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-02-16 10:35:13 +0100 (Tue, 16 Feb 2016)");
  script_name("Cisco Prime Collaboration Provisioning Web Interface Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of the Cisco Prime Collaboration
  Provisioning Web Interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

buf = http_get_cache( port:port, item:"/" );

if( buf =~ "^HTTP/1\.[01] 302" && "/cupm/Login" >< buf ) {

  cpe = "cpe:/a:cisco:prime_collaboration_provisioning";
  vers = "unknown";

  url = "/dfcweb/lib/cupm/nls/applicationproperties.js";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "Cisco Prime Collaboration" >!< buf ) exit( 0 );

  set_kb_item( name:"cisco/cupm/detected", value:TRUE );
  set_kb_item( name:"cisco/cupm/http/detected", value:TRUE );
  set_kb_item( name:"cisco/cupm/http/version", value:vers );
  set_kb_item( name:"cisco/cupm/http/port", value:port );

  # not granular enough for later use. Detected via ssh: 10.0.0.791, detected via http: 10.0
  version = eregmatch( pattern:'file_version: "Version ([^"]+)",', string:buf );
  if( ! isnull( version[1] ) ) {
    vers = version[1];
    cpe += ":" + vers;
  }

  report = 'The Cisco Prime Collaboration Provisioning Web Interface is running at this port.\n' +
           'Version: ' + vers + '\n' +
           'CPE: ' + cpe + '\n';

  log_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
