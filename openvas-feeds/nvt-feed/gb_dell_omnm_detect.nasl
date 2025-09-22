# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141657");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-08 09:03:04 +0700 (Thu, 08 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell OpenManage Network Manager (OMNM) Detection");

  script_tag(name:"summary", value:"Detection of Dell OpenManage Network Manager (OMNM).

  The script sends a connection request to the server and attempts to detect Dell OpenManage Network Manager.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.dell.com/en-us/work/shop/povw/dell-openmanage-network-manager");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

res = http_get_cache(port: port, item: "/login");

if ("<title>Login - OMNM</title>" >< res && "/html/js/barebone.jsp" >< res) {
  version = "unknown";

  set_kb_item(name: "dell_omnm/detected", value: TRUE);

  cpe = 'cpe:/a:dell:openmanage_network_manager';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Dell OpenManage Network Manager", version: version, install: "/",
                                           cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
