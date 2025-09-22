# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105522");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2016-01-19 18:05:56 +0100 (Tue, 19 Jan 2016)");

  script_name("Cisco Firepower Management Center (FMC) Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Cisco Firepower Management Center (FMC)
  detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_firepower_management_center_ssh_login_detect.nasl", "gb_cisco_firepower_management_center_http_detect.nasl");
  script_mandatory_keys("cisco/firepower_management_center/detected");

  exit(0);
}

if (!get_kb_item("cisco/firepower_management_center/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
detected_build = "unknown";
location = "/";

foreach source (make_list("ssh-login", "http")) {
  model_list = get_kb_list("cisco/firepower_management_center/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "cisco/firepower_management_center/model", value: model);
      break;
    }
  }

  version_list = get_kb_list("cisco/firepower_management_center/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("cisco/firepower_management_center/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "cisco/firepower_management_center/build", value: build);
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:cisco:firepower_management_center:");
if (!cpe)
  cpe = "cpe:/a:cisco:firepower_management_center";

if (http_ports = get_kb_list("cisco/firepower_management_center/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concUrl = get_kb_item("cisco/firepower_management_center/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += "  Concluded from version/product identification location: " + concUrl + '\n';

    concl = get_kb_item("cisco/firepower_management_center/http/" + port + "/concluded");
    if (concl)
      extra += '  Concluded from version/product identification result:\n' + concl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (ssh_login_ports = get_kb_list("cisco/firepower_management_center/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH login on port " + port + '/tcp\n';

    concluded = get_kb_item("cisco/firepower_management_center/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
  }
}

# nb: More detailed version fingerprinting is available / done via gather-package-list.nasl
os_register_and_report(os: "Cisco Fire Linux OS", cpe: "cpe:/o:cisco:fire_linux_os", runs_key: "unixoide",
                       desc: "Cisco Firepower Management Center (FMC) Detection Consolidation");

report = build_detection_report(app: "Cisco Firepower Management Center (FMC)", version: detected_version,
                                install: location, cpe: cpe,
                                extra: "Build: " + detected_build + '\nModel: ' + detected_model);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
