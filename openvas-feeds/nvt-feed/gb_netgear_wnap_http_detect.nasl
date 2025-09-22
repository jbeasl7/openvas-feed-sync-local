# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141739");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-11-29 15:59:23 +0700 (Thu, 29 Nov 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NETGEAR WNAP/WNDAP Device Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of NETGEAR WNAP/WNDAP devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/index.php?page=master&menu1=Help&menu2=&menu3=&menu4=");

if ("<title>Netgear</title>" >< res && res =~ "products/WN(D)?AP[0-9]+\.asp") {
  set_kb_item(name: "netgear_wnap/detected", value:TRUE );
  set_kb_item(name: "netgear_wnap/http/detected", value: TRUE);
  set_kb_item(name: "netgear_wnap/http/port", value: port);

  # http://kbserver.netgear.com/products/WNDAP360.asp
  mod = eregmatch(pattern: "products/(WN(D)?AP[0-9]+)\.asp", string: res);
  if (!isnull(mod[1]))
    set_kb_item(name: "netgear_wnap/http/" + port + "/model", value: mod[1]);

  exit(0);
}

exit(0);
