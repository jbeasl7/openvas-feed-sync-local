# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103729");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2013-06-05 13:20:54 +0200 (Wed, 05 Jun 2013)");
  script_name("Siemens Gigaset SX762 Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("SiemensGigaset-Server/banner");

  script_tag(name:"summary", value:"HTTP based detection of Siemens Gigaset SX762.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: SiemensGigaset-Server" >!< banner)
  exit(0);

url = "/UE/welcome_login.html";
buf = http_get_cache(item:url, port:port);

if("<title>Gigaset sx762" >< buf) {

  set_kb_item(name:"siemens/gigaset/sx762/detected",value:TRUE);
  set_kb_item(name:"siemens/gigaset/sx762/http/detected",value:TRUE);

  cpe = "cpe:/a:siemens:gigaset_sx762";

  register_product(cpe:cpe, location:port + "/tcp", port:port, service:"www");

  log_message(data:"The remote Host is a Siemens Gigaset SX762 device.\nCPE: " + cpe + "\n", port:port);
  exit(0);
}

exit(0);
