# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143934");
  script_version("2024-10-10T07:25:31+0000");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2020-05-19 06:06:15 +0000 (Tue, 19 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenVPN Access Server Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of OpenVPN Access Server.

  This script performs HTTP based detection of OpenVPN Access Server.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("OpenVPN_AS/banner");
  script_require_ports("Services/www", 443, 8443, 9443);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

banner = http_get_remote_headers(port: port);
if (banner !~ "Server\s*:\s*OpenVPN-AS")
  exit(0);

set_kb_item(name: "openvpn/access_server/detected", value: TRUE);
set_kb_item(name: "openvpn/access_server/http/port", value: port);

concluded = eregmatch(pattern: "Server\s*:\s*OpenVPN-AS", string: banner, icase: TRUE);
set_kb_item(name: "openvpn/access_server/http/" + port + "/concluded", value: concluded[0]);

version = "unknown";

set_kb_item(name: "openvpn/access_server/http/" + port + "/version", value: version);

exit(0);
