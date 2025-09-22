# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153401");
  script_version("2024-11-26T07:35:52+0000");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-07 13:59:15 +0000 (Thu, 07 Nov 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM WebSphere Application Server (Traditional and Liberty) Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_ibm_websphere_giop_detect.nasl",
                      "gb_ibm_websphere_http_detect.nasl");
  script_mandatory_keys("ibm/websphere_or_liberty/detected");

  script_tag(name:"summary", value:"Consolidation of IBM WebSphere Application Server detections
  (Traditional and Liberty).");

  script_xref(name:"URL", value:"https://www.ibm.com/products/websphere-application-server");
  script_xref(name:"URL", value:"https://www.ibm.com/docs/en/was-liberty/base?topic=liberty-overview");

  exit(0);
}

if (!get_kb_item("ibm/websphere_or_liberty/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("giop", "http")) {
  version_list = get_kb_list("ibm/websphere_or_liberty/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:websphere_application_server:");
if (!cpe)
  cpe = "cpe:/a:ibm:websphere_application_server";

if (get_kb_item("ibm/websphere/liberty/detected")) {
  app_name = "IBM WebSphere Application Server Liberty";
} else {
  app_name = "IBM WebSphere Application Server";
  set_kb_item(name: "ibm/websphere/detected", value: TRUE);
}

if (http_ports = get_kb_list("ibm/websphere_or_liberty/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '\n';

    concluded = get_kb_item("ibm/websphere_or_liberty/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("ibm/websphere_or_liberty/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (giop_ports = get_kb_list("ibm/websphere_or_liberty/giop/port")) {
  foreach port (giop_ports) {
    extra += "GIOP on port " + port + '/tcp\n';

    concluded = get_kb_item("ibm/websphere_or_liberty/giop/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "giop");
  }
}

report = build_detection_report(app: app_name, version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
