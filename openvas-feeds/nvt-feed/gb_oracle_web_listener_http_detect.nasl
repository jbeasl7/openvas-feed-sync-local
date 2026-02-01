# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113605");
  script_version("2026-01-27T05:49:07+0000");
  script_tag(name:"last_modification", value:"2026-01-27 05:49:07 +0000 (Tue, 27 Jan 2026)");
  script_tag(name:"creation_date", value:"2019-12-02 11:41:10 +0200 (Mon, 02 Dec 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Oracle Web Listener Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Oracle/banner");

  script_tag(name:"summary", value:"HTTP based detection of Oracle Web Listener (a component of the
  Oracle Application Server(AS)).");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port( default: 80 );

buf = http_get_remote_headers( port: port );

if( buf =~ "Server\s*:.*Oracle_Web_Listener" ) {
  set_kb_item( name: "oracle/web_listener/detected", value: TRUE );
  set_kb_item( name: "oracle/web_listener/http/detected", value: TRUE );

  version = "unknown";

  ver = eregmatch( string: buf, pattern: "Oracle_Web_Listener/([0-9.]+)" );
  if( ! isnull( ver[1] ) )
    version = ver[1];

  register_and_report_cpe( app: "Oracle Web Listener",
                           ver: version,
                           concluded: ver[0],
                           base: "cpe:/a:oracle:web_listener:",
                           expr: "([0-9.]+)",
                           insloc: port + "/tcp",
                           regPort: port,
                           regService: "www" );
}

exit( 0 );
