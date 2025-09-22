# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105411");
  script_version("2025-01-16T05:37:14+0000");
  script_tag(name:"last_modification", value:"2025-01-16 05:37:14 +0000 (Thu, 16 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-10-19 11:11:38 +0200 (Mon, 19 Oct 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Juniper Networks Junos Space Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Juniper Networks Junos Space.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = "/mainui/";

res = http_get_cache( port:port, item:url );

if( "Junos Space Login</title>" >!< res || "j_username" >!< res )
  exit( 0 );

set_kb_item( name:"juniper/junos/space/detected", value:TRUE );
set_kb_item( name:"juniper/junos/space/http/detected", value:TRUE );
set_kb_item( name:"juniper/junos/space/http/port", value:port );

version = "unknown";
build = "unknown";
conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

set_kb_item( name:"juniper/junos/space/http/" + port + "/version", value: version);
set_kb_item( name:"juniper/junos/space/http/" + port + "/build", value: build);
set_kb_item( name:"juniper/junos/space/http/" + port + "/concludedUrl", value: conclUrl);

exit( 0 );
