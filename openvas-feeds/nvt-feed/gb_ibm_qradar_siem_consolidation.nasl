# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152094");
  script_version("2024-04-18T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-04-18 05:05:33 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-16 05:17:14 +0000 (Tue, 16 Apr 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM QRadar SIEM Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_ibm_qradar_siem_ssh_login_detect.nasl",
                      "gb_ibm_qradar_siem_http_detect.nasl");
  script_mandatory_keys("ibm/qradar/siem/detected");

  script_tag(name:"summary", value:"Consolidation of IBM QRadar SIEM detections.");

  script_xref(name:"URL", value:"https://www.ibm.com/products/qradar-siem");

  exit(0);
}

if (!get_kb_item("ibm/qradar/siem/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

# nb: Currently only via authenticated SSH login extracted
foreach source (make_list("ssh-login")) {
  version_list = get_kb_list("ibm/qradar/siem/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:qradar_security_information_and_event_manager:");
if (!cpe)
  cpe = "cpe:/a:ibm:qradar_security_information_and_event_manager";

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", runs_key: "unixoide",
                       desc: "IBM QRadar SIEM Detection Consolidation");

if (http_ports = get_kb_list("ibm/qradar/siem/http/port")) {
  extra += 'Remote Detection over HTTP(s):\n';

  foreach port (http_ports) {
    extra += "  Port:     " + port + '/tcp\n';

    concludedUrl = get_kb_item("ibm/qradar/siem/http/" + port + "/concludedUrl");
    if (concludedUrl)
      extra += "  Concluded from version/product identification location: " + concludedUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (ssh_login_ports = get_kb_list("ibm/qradar/siem/ssh-login/port")) {
  extra += 'Local Detection over SSH:\n';

  foreach port (ssh_login_ports) {
    extra += "  Port:     " + port + '/tcp\n';

    conclLoc = get_kb_item("ibm/qradar/siem/ssh-login/" + port + "/conclLoc");
    if (conclLoc)
      extra += '  Concluded from version/product identification location:\n' + conclLoc;

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

report  = build_detection_report(app: "IBM QRadar SIEM", version: detected_version, install: location,
                                 cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
