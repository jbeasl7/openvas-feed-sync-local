# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152533");
  script_version("2025-04-02T05:40:12+0000");
  script_tag(name:"last_modification", value:"2025-04-02 05:40:12 +0000 (Wed, 02 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-07-02 08:21:39 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell / EMC Avamar Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_dell_avamar_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_dell_avamar_snmp_detect.nasl",
                        "gsf/gb_dell_avamar_ssh_login_detect.nasl");
  script_mandatory_keys("dell/avamar/detected");

  script_tag(name:"summary", value:"Consolidation of Dell / EMC Avamar detections.");

  script_xref(name:"URL", value:"https://www.dell.com/en-us/dt/data-protection/data-protection-suite/avamar-data-protection-software.htm");

  exit(0);
}

if (!get_kb_item("dell/avamar/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "snmp", "http")) {
  version_list = get_kb_list("dell/avamar/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe1 = build_cpe(value: detected_version, exp: "^([0-9.-]+)", base: "cpe:/a:dell:emc_avamar:");
cpe2 = build_cpe(value: version, exp: "^([0-9.-]+)", base: "cpe:/a:emc:avamar:");
if (!cpe1) {
  cpe1 = "cpe:/a:dell:emc_avamar";
  cpe2 = "cpe:/a:emc:avamar";
}

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", runs_key: "unixoide",
                       desc: "Dell / EMC Avamar Detection Consolidation");

if (http_ports = get_kb_list("dell/avamar/http/port")) {
  foreach port (http_ports) {
    extra = "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("dell/avamar/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("dell/avamar/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "www");
    register_product(cpe: cpe2, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("dell/avamar/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    concluded = get_kb_item("dell/avamar/snmp/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    concludedOID = get_kb_item("dell/avamar/snmp/" + port + "/concludedOID");
    if (concludedOID)
      extra += "  Concluded from version/product identification location (OID): " + concludedOID + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: cpe2, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ssh_login_ports = get_kb_list("dell/avamar/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH login via port " + port + '/tcp\n';

    concluded = get_kb_item("dell/avamar/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "ssh-login");
    register_product(cpe: cpe2, location: location, port: port, service: "ssh-login");
  }
}

report = build_detection_report(app: "Dell / EMC Avamar", version: detected_version, install: location,
                                cpe: cpe1);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
