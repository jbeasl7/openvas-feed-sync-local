# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144350");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-08-04 05:14:24 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Pulse Secure / Ivanti Connect Secure Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_pulse_connect_secure_snmp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_pulse_connect_secure_http_detect.nasl",
                        "gsf/gb_pulse_connect_secure_netconf_ssh_login_detect.nasl");
  script_mandatory_keys("pulsesecure/detected");

  script_tag(name:"summary", value:"Consolidation of Ivanti Connect Secure (formerly Pulse Secure
  Connect Secure) detections.");

  script_xref(name:"URL", value:"https://www.ivanti.com/products/connect-secure-vpn");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("pulsesecure/detected"))
  exit(0);

detected_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source (make_list("snmp", "http", "netconf/ssh")) {
  version_list = get_kb_list("pulsesecure/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list("pulsesecure/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "pulsesecure/model", value: detected_model);
      break;
    }
  }
}

name = "Pulse Secure / Ivanti Connect Secure";

# Examples from https://www.ivanti.com/resources/v/doc/ivi/2516/9c01b1c709cb:
#
# Hardware:
# - ISA-6000
# - ISA-8000
# - PSA-3000
# - PSA-5000
# - PSA-7000
#
# Virtual:
# - ISA-4000-V
# - ISA-6000-V
# - ISA-8000-V
# - PSA-3000-V
# - PSA-5000-V
# - PSA-7000-V

if (detected_model != "unknown") {

  # nb: We have the "virtual" appliance here and thus are using a "cpe:/a" based CPE
  if ("-V" >< detected_model) {
    appliance_cpe1 = "cpe:/a:ivanti:" + tolower(detected_model);
    appliance_cpe2 = "cpe:/a:pulsesecure:" + tolower(detected_model);
  } else {
    appliance_cpe1 = "cpe:/h:ivanti:" + tolower(detected_model);
    appliance_cpe2 = "cpe:/h:pulsesecure:" + tolower(detected_model);
  }
}
# nb: If the model is unknown we're not registering it at all as we can't differ between a "cpe:/a:"
# and a "cpe:/h:" CPE and don't want to register both (at least currently).

# The most recent vendor is Ivanti
software_cpe1 = build_cpe(value: tolower(detected_version), exp: "^([0-9.]+)(r[0-9.]+)?", base: "cpe:/a:ivanti:connect_secure:");
# After Juniper the second vendor was Pulse Secure:
# https://www.juniper.net/documentation/en_US/release-independent/junos-pulse/information-products/pathway-pages/junos-pulse/index.html
software_cpe2 = build_cpe(value: tolower(detected_version), exp: "^([0-9.]+)(r[0-9.]+)?", base: "cpe:/a:pulsesecure:pulse_connect_secure:");
# Earlier Juniper Product, formerly Juniper Junos Pulse, cpe:/a:juniper:pulse_connect_secure
software_cpe3 = build_cpe(value: tolower(detected_version), exp: "^([0-9.]+)(r[0-9.]+)?", base: "cpe:/a:juniper:pulse_connect_secure:");
if (!software_cpe1) {
  software_cpe1 = "cpe:/a:ivanti:connect_secure";
  software_cpe2 = "cpe:/a:pulsesecure:pulse_connect_secure";
  software_cpe3 = "cpe:/a:juniper:pulse_connect_secure";
}

# The appliance/server runs only on Linux based systems.
os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "Pulse Secure / Ivanti Connect Secure Detection Consolidation", runs_key: "unixoide");

if (http_ports = get_kb_list("pulsesecure/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    conclUrl = get_kb_item("pulsesecure/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    concluded = get_kb_item("pulsesecure/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    http_extra = get_kb_item("pulsesecure/http/" + port + "/extra");
    if (http_extra)
      extra += '  ' + http_extra + '\n';

    register_product(cpe: software_cpe1, location: location, port: port, service: "www");
    register_product(cpe: software_cpe2, location: location, port: port, service: "www");
    register_product(cpe: software_cpe3, location: location, port: port, service: "www");
    register_product(cpe: appliance_cpe1, location: location, port: port, service: "www");
    register_product(cpe: appliance_cpe2, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("pulsesecure/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';
    concluded = get_kb_item("pulsesecure/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  SNMP Banner:  ' + concluded + '\n';

    register_product(cpe: software_cpe1, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: software_cpe2, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: software_cpe3, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: appliance_cpe1, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: appliance_cpe1, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (netconf_ssh_ports = get_kb_list("pulsesecure/netconf/ssh/port")) {
  foreach port (netconf_ssh_ports) {
    extra += 'NETCONF over SSH on port ' + port + '/tcp\n';
    concluded = get_kb_item("pulsesecure/netconf/ssh/" + port + "/concluded");
    if (concluded)
      extra += '  NETCONF "<get-config>" banner/response for the "system->info" subtree:\n' + concluded + '\n';

    register_product(cpe: software_cpe1, location: location, port: port, service: "netconf-ssh");
    register_product(cpe: software_cpe2, location: location, port: port, service: "netconf-ssh");
    register_product(cpe: software_cpe3, location: location, port: port, service: "netconf-ssh");
    register_product(cpe: appliance_cpe1, location: location, port: port, service: "netconf-ssh");
    register_product(cpe: appliance_cpe1, location: location, port: port, service: "netconf-ssh");
  }
}

report = build_detection_report(app: name, version: detected_version, install: location, cpe: software_cpe1);

if (appliance_cpe1)
  report += '\n\n' + build_detection_report(app: name + " " + detected_model, skip_version: TRUE, install: location, cpe: appliance_cpe1);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
