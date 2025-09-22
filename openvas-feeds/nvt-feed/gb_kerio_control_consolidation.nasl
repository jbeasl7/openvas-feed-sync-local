# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153820");
  script_version("2025-01-22T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-21 04:42:57 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kerio Control Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_kerio_control_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_kerio_control_snmp_detect.nasl",
                        "gsf/gb_kerio_control_ssh_login_detect.nasl");
  script_mandatory_keys("kerio/control/detected");

  script_tag(name:"summary", value:"Consolidation of Kerio Control detections.");

  script_xref(name:"URL", value:"https://gfi.ai/products-and-solutions/network-security-solutions/keriocontrol");

  exit(0);
}

if (!get_kb_item("kerio/control/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_build = "unknown";
location = "/";

foreach source (make_list("ssh-login", "snmp", "http")) {
  version_list = get_kb_list("kerio/control/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

build_list = get_kb_list("kerio/control/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "kerio/control/build", value: detected_build);
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:kerio:control:");
os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:kerio:control_operating_system:");
if (!cpe) {
  cpe = "cpe:/a:kerio:control";
  os_cpe = "cpe:/o:kerio:control_operating_system";
}

os_register_and_report(os: "Kerio Control Operating System", cpe: os_cpe, runs_key: "unixoide",
                       desc: "Kerio Control Detection Consolidation");

if (http_ports = get_kb_list("kerio/control/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("kerio/control/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("kerio/control/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
    register_product(cpe: os_cpe, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("kerio/control/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '\n';

    banner = get_kb_item("kerio/control/snmp/" + port + "/concluded");
    if (banner)
      extra += "  SNMP banner: " + banner + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe, location: location, port: port, service: "www", proto: "udp");
  }
}

if (ssh_login_ports = get_kb_list("kerio/control/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH Login on port " + port + '/tcp\n';

    concluded = get_kb_item("kerio/control/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "ssh-login");
    register_product(cpe: os_cpe, location: location, port: port, service: "ssh-login");
  }
}

report = build_detection_report(app: "Kerio Control", version: detected_version, build: detected_build,
                                cpe: cpe, install: location);

if( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
