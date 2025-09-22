# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141310");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-17 16:08:27 +0200 (Tue, 17 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("QNAP Q'center Virtual Appliance Detection");

  script_tag(name:"summary", value:"Detection of QNAP Q'center Virtual Appliance.

The script sends a connection request to the server and attempts to detect QNAP Q'center Virtual Appliance and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081, 9443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.qnap.com/solution/qcenter/index.php");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8081);

res = http_get_cache(port: port, item: "/qcenter/qcenter/index.html");

if ("<title>Q'center</title>" >< res && 'src="settings.js' >< res) {
  version = "unknown";

  vers = eregmatch(pattern: "\.js\?_v=([0-9.]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "qnap_qcenter/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:qnap:qcenter:");
  if (!cpe)
    cpe = 'cpe:/a:qnap:qcenter';

  register_product(cpe: cpe, location: "/qcenter", port: port, service: "www");

  log_message(data: build_detection_report(app: "QNAP Q'center Virtual Appliance", version: version,
                                           install: "/qcenter", cpe: cpe, concluded: vers[0]),
              port: port);
  exit(0);
}

exit(0);
