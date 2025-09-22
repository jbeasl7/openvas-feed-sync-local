# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152320");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-05-29 07:59:35 +0000 (Wed, 29 May 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Check Point Firewall Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_checkpoint_fw_http_detect.nasl",
                      "check_point_fw1_secureremote_detect.nasl",
                      "gb_checkpoint_fw_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_checkpoint_fw_snmp_detect.nasl",
                        "gsf/gb_checkpoint_fw_sslextender_http_detect.nasl");
  script_mandatory_keys("checkpoint/firewall/detected");

  script_tag(name:"summary", value:"Consolidation of Check Point Firewall detections.");

  script_xref(name:"URL", value:"https://www.checkpoint.com/");

  exit(0);
}

if (!get_kb_item("checkpoint/firewall/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_build = "unknown";
location = "/";

# nb: Currently no version extracted from SSL Network Extender Portal or FireWall-1 (FW-1)
foreach source (make_list("ssh-login", "snmp", "http")) {
  version_list = get_kb_list("checkpoint/firewall/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("checkpoint/firewall/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "checkpoint/firewall/build", value: build);
      break;
    }
  }
}

os_cpe = build_cpe(value: tolower(detected_version), exp: "^(r[0-9.]+)", base: "cpe:/o:checkpoint:gaia_os:");
if (!os_cpe)
  os_cpe = "cpe:/o:checkpoint:gaia_os";

# nb: Since `R80` released in around 2016 it seems the devices are only running Gaia so we're only
# registering this here for now.
os_register_and_report(os: "Check Point Gaia", cpe: os_cpe, runs_key: "unixoide",
                       desc: "Check Point Firewall Detection Consolidation");

if (http_ports = get_kb_list("checkpoint/firewall/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("checkpoint/firewall/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("checkpoint/firewall/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
  }
}

if (extender_ports = get_kb_list("checkpoint/firewall/ssl_extender/port")) {
  foreach port (extender_ports) {
    extra += "SSL Network Extender Portal via HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("checkpoint/firewall/ssl_extender/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    conclUrl = get_kb_item("checkpoint/firewall/ssl_extender/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: os_cpe, location: location, port: port, service: "ssl-extender");
  }
}

if (snmp_ports = get_kb_list("checkpoint/firewall/snmp/port")) {
  foreach port (snmp_ports) {
    extra += "SNMP on port " + port + '/udp\n';

    concludedVers = get_kb_item("checkpoint/firewall/snmp/" + port + "/concludedSwVers");
    concludedVersOID = get_kb_item("checkpoint/firewall/snmp/" + port + "/concludedSwVersOID");
    if (concludedVers && concludedVersOID)
      extra += '  Version concluded from:     "' + concludedVers + '" via OID: "' + concludedVersOID + '"\n';

    concludedBuild = get_kb_item("checkpoint/firewall/snmp/" + port + "/concludedBuildVers");
    concludedBuildOID = get_kb_item("checkpoint/firewall/snmp/" + port + "/concludedBuildVersOID");
    if (concludedBuild && concludedBuildOID)
      extra += '  Build concluded from:       "' + concludedBuild + '" via OID: "' + concludedBuildOID + '"\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ssh_login_ports = get_kb_list("checkpoint/firewall/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH login on port " + port + '/tcp\n';

    concluded = get_kb_item("checkpoint/firewall/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "ssh-login");
  }
}

if (fw1_topology_ports = get_kb_list("checkpoint/firewall/fw1_topology/port")) {
  foreach port (fw1_topology_ports) {
    extra += "FireWall-1 (FW-1) SecureRemote (SecuRemote) on port " + port + '/tcp\n';
    register_product(cpe: os_cpe, location: location, port: port, service: "fw1-topology");
  }
}

report = build_detection_report(app: "Check Point Firewall", version: detected_version,
                                build: detected_build, install: location, cpe: os_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
