# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801244");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("bozotic HTTP server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("bozohttpd/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"This script finds the running bozotic HTTP server version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port:port);
if(! banner || "erver: bozohttpd" >!< banner)
  exit(0);

version = "unknown";
ver = eregmatch(pattern:"bozohttpd/([0-9.]+)", string:banner);
if(ver[1])
  version = ver[1];

set_kb_item(name:"bozohttpd/detected", value:TRUE);

register_and_report_cpe(app:"bozotic HTTP server", ver:version, concluded:ver[0], regService:"www", regPort:port, base:"cpe:/a:eterna:bozohttpd:", expr:"^([0-9.]+)", insloc:port + "/tcp");

exit(0);
