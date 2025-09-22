# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125294");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-01 10:47:00 +0000 (Mon, 01 Sep 2025)");

  script_name("Elastic Logstash Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9600);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Elastic Logstash.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:9600 );
install = "/";
version = "unknown";

res = http_get_cache( item:install, port:port );
if( res && "version" >< res && ( "logstash" >< res || "ephemeral_id" >< res ) ) {

  vers = eregmatch( string:res, pattern:'"version":"([0-9a-z.]+)",', icase:TRUE );
  if( ! isnull( vers[1] ) )
    version = chomp( vers[1] );

  set_kb_item( name:"elastic/logstash/detected", value:TRUE );
  set_kb_item( name:"elastic/logstash/http/detected", value:TRUE );
  set_kb_item( name:"elastic/logstash/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + res );
}

exit( 0 );
