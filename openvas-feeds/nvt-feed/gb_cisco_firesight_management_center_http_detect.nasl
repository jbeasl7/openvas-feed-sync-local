# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106160");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-29 14:46:43 +0700 (Fri, 29 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco FireSIGHT Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Cisco FireSIGHT Management
Center");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/products/security/firesight-management-center/index.html");


  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:443);

res = http_get_cache(item: "/login.cgi", port: port);

if ("<b>Sourcefire Support</b>" >< res && "<b>Cisco Support</b>" >< res) {
  version = "unknown";
  build = "unknown";

  vers_build = eregmatch(string: res, pattern: "login.css\?v=([0-9.-]+)");
  if (!isnull(vers_build[1])) {
    tmp = split(vers_build[1], sep: "-", keep: FALSE);
    if (!isnull(tmp[0]))
      version = tmp[0];
    if (!isnull(tmp[1]))
      build = tmp[1];
  }
  else
    exit(0);

  if (version != "unknown")
    set_kb_item(name: "cisco_firesight_management_center/version", value: version);

  if (build != "unknown")
    set_kb_item(name: "cisco_firesight_management_center/build", value: build);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:firesight_management_center:");
  if (!cpe)
    cpe = "cpe:/a:cisco:firesight_management_center";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Cisco FireSIGHT Management Center", version: version,
                                           install: "/", cpe: cpe, concluded: vers_build[0]),
              port: port);

  exit(0);
}

exit(0);
