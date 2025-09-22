# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105961");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2015-03-06 15:14:16 +0700 (Fri, 06 Mar 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SolarWinds IP Address Manager (IPAM) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 8787);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of SolarWinds IP Address Manager (IPAM).");

  script_xref(name:"URL", value:"http://www.solarwinds.com/products/orion/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:8787);

if (!http_can_host_asp(port:port))
  exit(0);

dir = "/Orion";
url = dir + "/Login.aspx";
buf = http_get_cache(item:url, port:port);
if (!buf)
  exit(0);

if ("SolarWinds Platform" >< buf || "SolarWinds Orion" >< buf || "Orion Platform" >< buf) {

  ipam = eregmatch(string:buf, pattern: "IPAM ([0-9.]+)", icase:TRUE);
  if (!isnull(ipam)) {

    vers = "unknown";
    if (!isnull(ipam[1]))
      vers = chomp(ipam[1]);

    set_kb_item(name:"solarwinds/ipam/detected", value:TRUE);
    set_kb_item(name:"solarwinds/ipam/http/detected", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:solarwinds:ip_address_manager_web_interface:");
    if (!cpe)
      cpe = "cpe:/a:solarwinds:ip_address_manager_web_interface";

    register_product(cpe:cpe, location:dir, port:port, service:"www");

    log_message(data:build_detection_report(app:"SolarWinds IP Address Manager (IPAM)", version:vers,
                                            install:dir, cpe:cpe,
                                            concluded: ipam[0]),
                port:port);
  }
}

exit(0);
