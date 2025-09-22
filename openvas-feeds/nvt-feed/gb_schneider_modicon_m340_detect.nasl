# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103856");
  script_version("2024-09-17T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-09-17 05:05:45 +0000 (Tue, 17 Sep 2024)");
  script_tag(name:"creation_date", value:"2013-12-16 11:11:45 +0100 (Mon, 16 Dec 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Schneider Electric Modicon M340 Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Schneider-WEB/banner");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.se.com");

  script_tag(name:"summary", value:"HTTP based detection of Schneider Electric Modicon M340
  devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || banner !~ "Server\s*:\s*Schneider-WEB")
  exit(0);

url = "/html/english/index.htm";
req = http_get(item:url, port:port);

buf = http_send_recv(port:port, data:req, bodyonly:TRUE);
if(!buf || buf !~ "<title>.* (BMX P34) .*</title>")
  exit(0);

set_kb_item(name:"schneider_modicon/m340/detected", value:TRUE);
set_kb_item(name:"schneider_modicon/m340/http/detected", value:TRUE);

cpe = "cpe:/h:schneider-electric:modicon_m340";
register_product(cpe:cpe, location:"/", port:port, service: "www");
log_message(data: 'The remote Host is a Schneider Modicon M340 device.\nCPE: ' + cpe + '\nLocation: /\n', port:port);

exit(0);
