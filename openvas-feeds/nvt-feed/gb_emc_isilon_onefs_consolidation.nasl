# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143673");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-04-06 03:14:31 +0000 (Mon, 06 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell EMC PowerScale OneFS (Isilion OneFS) Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_emc_isilon_onefs_ftp_detect.nasl", "gb_emc_isilon_onefs_ntp_detect.nasl",
                      "gb_emc_isilon_onefs_snmp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_emc_isilon_onefs_http_detect.nasl");
  script_mandatory_keys("dell/emc_isilon/onefs/detected");

  script_tag(name:"summary", value:"Consolidation of Dell EMC PowerScale OneFS (formerly Isilion
  OneFS) detections.");

  script_xref(name:"URL", value:"https://www.delltechnologies.com/en-us/storage/powerscale.htm");

  exit(0);
}

if (!get_kb_item("dell/emc_isilon/onefs/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

# nb: No version extraction via HTTP
foreach source (make_list("ftp", "snmp", "ntp")) {
  version_list = get_kb_list("dell/emc_isilon/onefs/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

app_cpe1 = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:dell:emc_powerscale_onefs:");
app_cpe2 = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:dell:emc_isilon_onefs:");
if (!app_cpe1) {
  app_cpe1 = "cpe:/a:dell:emc_powerscale_onefs";
  app_cpe2 = "cpe:/a:dell:emc_isilon_onefs";
}

os_cpe1 = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:dell:emc_powerscale_onefs:");
os_cpe2 = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:emc:isilon_onefs:");
if (!os_cpe1) {
  os_cpe1 = "cpe:/o:dell:emc_powerscale_onefs";
  os_cpe2 = "cpe:/o:emc:isilon_onefs";
}

os_register_and_report(os: "Dell EMC PowerScale OneFS", cpe: os_cpe1, desc: "Dell EMC PowerScale OneFS (Isilion OneFS) Detection Consolidation",
                       runs_key: "unixoide");
os_register_and_report(os: "EMC Isilon OneFS", cpe: os_cpe2, desc: "Dell EMC PowerScale OneFS (Isilion OneFS) Detection Consolidation",
                       runs_key: "unixoide");

if (http_ports = get_kb_list("dell/emc_isilon/onefs/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    conclUrl = get_kb_item("dell/emc_isilon/onefs/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: app_cpe1, location: location, port: port, service: "www");
    register_product(cpe: app_cpe2, location: location, port: port, service: "www");
  }
}

if (ftp_ports = get_kb_list("dell/emc_isilon/onefs/ftp/port")) {
  foreach port (ftp_ports) {
    extra += 'FTP on port ' + port + '/tcp\n';

    concluded = get_kb_item("dell/emc_isilon/onefs/ftp/" + port + "/concluded");
    if (concluded)
      extra += '  FTP Banner: ' + concluded + '\n';

    register_product(cpe: app_cpe1, location: location, port: port, service: "ftp");
    register_product(cpe: app_cpe2, location: location, port: port, service: "ftp");
  }
}

if (snmp_ports = get_kb_list("dell/emc_isilon/onefs/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item("dell/emc_isilon/onefs/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  SNMP Banner: ' + concluded + '\n';

    register_product(cpe: app_cpe1, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: app_cpe2, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (ntp_ports = get_kb_list("dell/emc_isilon/onefs/ntp/port")) {
  foreach port (ntp_ports) {
    extra += 'NTP on port ' + port + '/udp\n';

    concluded = get_kb_item("dell/emc_isilon/onefs/ntp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: app_cpe1, location: location, port: port, service: "ntp", proto: "udp");
    register_product(cpe: app_cpe2, location: location, port: port, service: "ntp", proto: "udp");
  }
}

report = build_detection_report(app: "Dell EMC PowerScale OneFS", version: detected_version, install: location, cpe: app_cpe1);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
