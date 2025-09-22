# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149142");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2023-01-16 04:56:17 +0000 (Mon, 16 Jan 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Juniper Networks Junos OS Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_juniper_junos_snmp_detect.nasl",
                      "gb_juniper_junos_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_juniper_junos_http_detect.nasl",
                        "gsf/gb_juniper_junos_netconf_ssh_login_detect.nasl",
                        "gsf/gb_juniper_junos_junoscript_detect.nasl");
  script_mandatory_keys("juniper/junos/detected");

  script_tag(name:"summary", value:"Consolidation of Juniper Networks Junos OS detections.");

  script_xref(name:"URL", value:"https://www.juniper.net/us/en/products/network-operating-system/junos-os.html");

  exit(0);
}

if (!get_kb_item("juniper/junos/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_model = "unknown";
detected_build = "unknown";
location = "/";
os_name = "Juniper Networks Junos OS";
hw_name = "Juniper Networks ";

foreach source (make_list("ssh-login", "snmp", "http", "junoscript", "netconf/ssh")) {
  model_list = get_kb_list("juniper/junos/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "juniper/junos/model", value: detected_model);
      break;
    }
  }

  version_list = get_kb_list("juniper/junos/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("juniper/junos/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      set_kb_item(name: "juniper/junos/build", value: detected_build);
      break;
    }
  }
}

os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+[A-Z].*)", base: "cpe:/o:juniper:junos:");
if (!os_cpe)
  os_cpe = "cpe:/o:juniper:junos";

os_register_and_report(os: os_name, version: detected_version, cpe: os_cpe, desc: "Juniper Networks Junos OS Detection Consolidation",
                       full_cpe: TRUE, runs_key: "unixoide");

if (detected_model != "unknown") {
  hw_name += detected_model;
  if (detected_model !~ "^v(SRX|VMX|QFX)")
    hw_cpe = "cpe:/h:juniper:" + tolower(detected_model);
  else
    hw_cpe = "cpe:/a:juniper:" + tolower(detected_model);
}

if (snmp_ports = get_kb_list("juniper/junos/snmp/port")) {
  extra += 'Remote Detection over SNMP:\n';

  foreach port (snmp_ports) {
    extra += "  Port:                   " + port + '/udp\n';

    concluded = get_kb_item("juniper/junos/snmp/" + port + "/concluded");
    if (concluded)
      extra += "  SNMP Banner:            " + concluded + '\n';

    concludedMod = get_kb_item("juniper/junos/snmp/" + port + "/concludedMod");
    concludedModOID = get_kb_item("juniper/junos/snmp/" + port + "/concludedModOID");
    if (concludedMod && concludedModOID)
      extra += '  Concluded model from:   "' + concludedMod + '" via OID: "' + concludedModOID + '"\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (http_ports = get_kb_list("juniper/junos/http/port")) {
  if (extra)
    extra += '\n';

  extra += 'Remote Detection over HTTP(s):\n';

  foreach port (http_ports) {
    extra += "  Port:                   " + port + '/tcp\n';

    concludedVers = get_kb_item("juniper/junos/http/" + port + "/concludedVers");
    concludedUrlVers = get_kb_item("juniper/junos/http/" + port + "/concludedUrlVers");
    if (concludedVers && concludedUrlVers)
      extra += '  Concluded version from: "' + concludedVers + '" via ' + concludedUrlVers + '\n';

    concludedMod = get_kb_item("juniper/junos/http/" + port + "/concludedMod");
    concludedUrlMod = get_kb_item("juniper/junos/http/" + port + "/concludedUrlMod");
    if (concludedMod && concludedUrlMod)
      extra += "  Concluded model from:   '" + concludedMod + "' via " + concludedUrlMod + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (junoscript_ports = get_kb_list("juniper/junos/junoscript/port")) {
  if (extra)
    extra += '\n';

  extra += 'Remote Detection over JUNOScript (XML):\n';

  foreach port (junoscript_ports) {
    extra += "  Port:                   " + port + '/tcp\n';

    concluded = get_kb_item("juniper/junos/junoscript/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded version from: "' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "junoscript");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "junoscript");
  }
}

if (ssh_ports = get_kb_list("juniper/junos/ssh-login/port")) {
  if (extra)
    extra += '\n';

  extra += 'Local Detection over SSH:\n';

  foreach port (ssh_ports) {
    extra += "  Port:                   " + port + '/tcp\n';

    concluded = get_kb_item("juniper/junos/ssh-login/" + port + "/concluded");
    if (concluded) {
      extra += '  Concluded from version/product identification result:\n' + concluded;
    }
  }

  register_product(cpe: os_cpe, location: location, port: port, service: "ssh-login");
  if (hw_cpe)
    register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
}

if (netconf_ssh_ports = get_kb_list("juniper/junos/netconf/ssh/port")) {
  if (extra)
    extra += '\n';

  extra += 'NETCONF over SSH:\n';

  foreach port (netconf_ssh_ports) {
    extra += "  Port:                   " + port + '/tcp\n';

    concluded = get_kb_item("juniper/junos/netconf/ssh/" + port + "/concluded");
    if (concluded) {
      extra += '  Concluded from version/product identification result:\n' + concluded;
    }
  }

  register_product(cpe: os_cpe, location: location, port: port, service: "netconf-ssh");
  if (hw_cpe)
    register_product(cpe: hw_cpe, location: location, port: port, service: "netconf-ssh");
}

report = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);

if (hw_cpe) {
  report += '\n\n';
  report += build_detection_report(app: hw_name, skip_version: TRUE, install: "/", cpe: hw_cpe);
}

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
