# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113663");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-03-31 13:21:43 +0100 (Tue, 31 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cassini / CassiniEx Web Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cassini/banner");

  script_tag(name:"summary", value:"HTTP based detection of the Cassini / CassiniEx Web Server.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/de-de/previous-versions/technical-content/bb979483(v=msdn.10)");
  script_xref(name:"URL", value:"https://soderlind.no/cassiniex-web-server/");

  exit(0);
}

CPE = "cpe:/a:microsoft:cassini";
APP = "Cassini";

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port( default: 80 );

banner = http_get_remote_headers( port: port );

if( banner =~ "Server\s*:\s*(Microsoft-)?Cassini" ) {

  set_kb_item( name: "microsoft/cassini/detected", value: TRUE );
  set_kb_item( name: "microsoft/cassini/http/detected", value: TRUE );

  version = "unknown";

  # nb:
  # - To tell http_can_host_asp from http_func.inc that the service is supporting this
  # - Product can definitely host ASP scripts
  # - TBD: replace_kb_item( name: "www/" + port + "/can_host_php", value: "yes" ); ?
  replace_kb_item( name: "www/" + port + "/can_host_asp", value: "yes" );

  # Server: Microsoft-Cassini/1.0.32007.0
  # Server: Cassini/4.0.1.6
  # Server: CassiniEx/4.4.1409.0
  # Server: CassiniEx/7.6.0.25
  # Server: CassiniEx/0.94.402.0
  ver = eregmatch( string: banner, pattern: "Server\s*:\s*(Microsoft-)?Cassini(Ex)?/([0-9.]+)", icase:TRUE );
  if( ! isnull( ver[3] ) )
    version = ver[3];

  if( ver[2] ) {
    CPE += "ex";
    APP += "Ex";
  }

  register_and_report_cpe( app: APP + " Web Server",
                           ver: version,
                           concluded: ver[0],
                           base: CPE + ":",
                           expr: "([0-9.]+)",
                           insloc: port + "/tcp",
                           regPort: port,
                           regService: "www" );
}

exit( 0 );
