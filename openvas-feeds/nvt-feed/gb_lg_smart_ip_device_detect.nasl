# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113270");
  script_version("2024-01-25T05:06:22+0000");
  script_tag(name:"last_modification", value:"2024-01-25 05:06:22 +0000 (Thu, 25 Jan 2024)");
  script_tag(name:"creation_date", value:"2018-09-18 11:50:00 +0200 (Tue, 18 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LG Smart IP Device Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of LG Smart IP devices.");

  script_xref(name:"URL", value:"https://www.lg.com/");

  exit(0);
}

CPE = "cpe:/h:lg:smart_ip:";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");

port = http_get_port( default: 8081 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";
  buf = http_get_cache( item: url, port: port );

  if( buf && buf =~ "<title>LG Smart IP Device</title>" ) {

    set_kb_item( name: "lg/smart_ip/detected", value: TRUE );
    set_kb_item( name: "lg/smart_ip/http/detected", value: TRUE );
    set_kb_item( name: "lg/smart_ip/port", value: port );
    set_kb_item( name: "lg/smart_ip/location", value: install );

    version = "unknown";

    # Version can only be acquired with valid credentials
    # For that, scripts/2018/lg/gb_lg_smart_ip_default_credentials.nasl might be of help

    register_and_report_cpe( app: "LG Smart IP Device",
                             base: CPE,
                             ver: version,
                             expr: "([0-9.]+)",
                             insloc: install,
                             regPort: port,
                             conclUrl: install );
    exit( 0 );
  }
}

exit( 0 );
