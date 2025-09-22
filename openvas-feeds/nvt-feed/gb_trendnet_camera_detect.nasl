# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112337");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-25 13:49:11 +0200 (Wed, 25 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Trendnet Internet Camera Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Trendnet Internet Camera devices.");

  script_xref(name:"URL", value:"https://www.trendnet.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

CPE = "cpe:/h:trendnet:ip_camera:";

port = http_get_port(default: 80);
banner = http_get_remote_headers(port:port);

if(banner && banner =~ 'www-authenticate:[ ]?basic[ ]?realm="netcam') {

  set_kb_item(name: "trendnet/ip_camera/detected", value: TRUE);
  set_kb_item(name: "trendnet/ip_camera/http_port", value: port);

  version = "unknown";

  register_and_report_cpe(app: "Trendnet IP Camera", ver: version, base: CPE, expr: "([^0-9.]+)", insloc: "/", regPort: port);
  exit(0);
}

exit(0);
