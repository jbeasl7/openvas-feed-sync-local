# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105458");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-18 13:39:52 +0100 (Wed, 18 Nov 2015)");

  script_name("Cisco Network Analysis Module (NAM) Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of the Cisco Network Analysis Module
  (NAM).");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = "/authenticate/login";

buf = http_get_cache( port:port, item:url );

if( ( "<title>NAM Login</title>" >< buf && "Cisco Prime" >< buf ) ||
    ( 'productName="Network Analysis Module"' >< buf ) ) {

  version = "unknown";

  set_kb_item( name:"cisco/nam/detected", value:TRUE );
  set_kb_item( name:"cisco/nam/http/detected", value:TRUE );
  set_kb_item( name:"cisco/nam/http/port", value:port );

  # productVersion="Version 6.4.2"
  vers = eregmatch( pattern:'productVersion="Version ([^"]+)"', string:buf );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item( name:"cisco/nam/http/" + port + "/concluded", value:vers[0] );
  }

  set_kb_item( name:"cisco/nam/http/" + port + "/version", value:version );
}

exit( 0 );
