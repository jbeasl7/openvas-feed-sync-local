# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140685");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-01-15 15:48:28 +0700 (Mon, 15 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("CommuniGate Pro Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of CommuniGate Pro.

The script sends a connection request to the server and attempts to detect CommuniGate Pro and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80, 443, 8010);
  script_mandatory_keys("CommuniGatePro/banner");

  script_xref(name:"URL", value:"https://www.communigate.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");


port = http_get_port(default: 8010);

banner = http_get_remote_headers(port: port);
if ("CommuniGatePro/" >!< banner)
  exit(0);

set_kb_item(name: "communigatepro/detected", value: TRUE);
set_kb_item(name: "communigatepro/http/detected", value: TRUE);
set_kb_item(name: "communigatepro/http/port", value: port);

vers = eregmatch(pattern: "CommuniGatePro/([0-9.]+)", string: banner);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "communigatepro/http/" + port + "/version", value: version);
  set_kb_item(name: "communigatepro/http/" + port + "/concluded", value: vers[0]);
}

exit(0);
