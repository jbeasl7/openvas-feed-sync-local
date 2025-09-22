# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107189");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-10-11 10:31:53 +0200 (Wed, 11 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Vacron NVR IP Surveillance Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Vacron NVR IP Surveillance.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default: 8081);

res = http_get_cache(item: "/", port: port);

if ("<title>VACRON NVR LOGIN</title>" >< res && "<strong>ADVANCES IN SECURITY SOLUTION</strong>" >< res) {

  version = "unknown";
  install = "/";

  set_kb_item(name:"vacron/nvr/detected", value:TRUE);
  set_kb_item(name:"vacron/nvr/http/detected", value:TRUE);

  cpe = build_cpe(value:version, base:"cpe:/a:vacron:nvr:");
  if (!cpe)
    cpe = "cpe:/a:vacron:nvr";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data:build_detection_report(app:"Vacron NVR IP Surveillance", version: version, install: install,
                                          cpe:cpe),
              port:port);
}

exit(0);
