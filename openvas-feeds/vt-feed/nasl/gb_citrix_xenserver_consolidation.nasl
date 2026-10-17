# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.158182");
  script_version("2026-10-16T05:49:01+0000");
  script_tag(name:"last_modification", value:"2026-10-16 05:49:01 +0000 (Fri, 16 Oct 2026)");
  script_tag(name:"creation_date", value:"2026-10-15 07:32:24 +0000 (Thu, 15 Oct 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Citrix XenServer Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_citrix_xenserver_http_detect.nasl");
  script_mandatory_keys("citrix/netscaler/detected");

  script_tag(name:"summary", value:"Consolidation of Citrix XenServer detections.");

  script_xref(name:"URL", value:"https://www.xenserver.com/");

  exit(0);
}

if (!get_kb_item("citrix/xenserver/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("http")) {
  version_list = get_kb_list("citrix/xenserver/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", runs_key: "unixoide",
                       desc: "Citrix XenServer Detection Consolidation");

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:citrix:xenserver:");
if (!cpe)
  cpe = "cpe:/a:citrix:xenserver";

if (http_ports = get_kb_list("citrix/xenserver/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '\n';

    concluded = get_kb_item("citrix/xenserver/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("citrix/xenserver/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

report = build_detection_report(app: "Citrix XenServer", version: version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
