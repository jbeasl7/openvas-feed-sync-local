# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103710");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-05-14 10:41:56 +0200 (Tue, 14 May 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("3Com OfficeConnect VPN Firewall Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of a 3Com OfficeConnect VPN Firewall.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:80);

buf = http_get_cache(item:"/", port:port);

if("<title>3Com - OfficeConnect VPN Firewall" >< buf) {
  version = "unknown";

  set_kb_item(name:"3com_officeconnect_vpn_firewall/detected", value:TRUE);

  cpe = "cpe:/o:hp:3com_officeconnect_gigabit_vpn_firewall_software";

  register_product(cpe:cpe, location:"/", port:port, service:"www");

  os_register_and_report(os:"3Com OfficeConnect VPN Firewall Software", cpe:cpe,
                         desc:"3Com OfficeConnect VPN Firewall Detection", runs_key:"unixoide");

  log_message(data:build_detection_report(app:"3Com OfficeConnect VPN Firewall", version:version, install:"/",
                                          cpe:cpe),
              port:port);

  exit(0);
}

exit(0);
