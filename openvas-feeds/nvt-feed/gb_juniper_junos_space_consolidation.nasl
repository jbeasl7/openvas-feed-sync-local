# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153760");
  script_version("2025-01-16T05:37:14+0000");
  script_tag(name:"last_modification", value:"2025-01-16 05:37:14 +0000 (Thu, 16 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-13 07:28:43 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Juniper Networks Junos Space Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_juniper_junos_space_http_detect.nasl",
                      "gb_juniper_junos_space_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_juniper_junos_space_ssh_detect.nasl");
  script_mandatory_keys("juniper/junos/space/detected");

  script_tag(name:"summary", value:"Consolidation of Juniper Networks Junos Space detections.");

  script_xref(name:"URL", value:"https://www.juniper.net/us/en/products/sdn-and-orchestration/junos-space-platform.html");

  exit(0);
}

if (!get_kb_item("juniper/junos/space/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
detected_build = "unknown";
location = "/";

# nb: Currently no version extracted via HTTP
foreach source (make_list("ssh-login", "ssh")) {
  version_list = get_kb_list("juniper/junos/space/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("juniper/junos/space/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "juniper/junos/space/build", value: detected_build);
      break;
    }
  }
}

app_cpe = build_cpe(value: tolower(detected_version), exp: "^([0-9r.]+)", base: "cpe:/a:juniper:junos_space:");
os_cpe = build_cpe(value: tolower(detected_version), exp: "^([0-9r.]+)", base: "cpe:/o:juniper:junos_space:");
if (!app_cpe) {
  app_cpe = "cpe:/a:juniper:junos_space";
  os_cpe = "cpe:/o:juniper:junos_space";
}

os_register_and_report(os: "Juniper Networks Junos Space", cpe: os_cpe, runs_key: "unixoide",
                       desc: "Juniper Networks Junos Space Detection Consolidation");

if (http_ports = get_kb_list("juniper/junos/space/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    conclUrl = get_kb_item("juniper/junos/space/http/" + port + "/concludedUrl");
    if (conclUrl)
      if (conclUrl)
        extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: app_cpe, location: location, port: port, service: "www");
    register_product(cpe: os_cpe, location: location, port: port, service: "www");
  }
}

if (ssh_ports = get_kb_list("juniper/junos/space/ssh/port")) {
  foreach port (ssh_ports) {
    extra += "SSH on port " + port + '/tcp\n';

    concluded = get_kb_item("juniper/junos/space/ssh/" + port + "/concluded");
    if (concluded)
      extra += "  SSH Login Banner: " + concluded + '\n';

    register_product(cpe: app_cpe, location: location, port: port, service: "ssh");
    register_product(cpe: os_cpe, location: location, port: port, service: "ssh");
  }
}

if (ssh_login_ports = get_kb_list("juniper/junos/space/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += "SSH Login via port " + port + '/tcp\n';

    concluded = get_kb_item("juniper/junos/space/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: app_cpe, location: location, port: port, service: "ssh-login");
    register_product(cpe: os_cpe, location: location, port: port, service: "ssh-login");
  }
}

report = build_detection_report(app: "Juniper Networks Junos Space", version: detected_version,
                                build: detected_build, install: location, cpe: os_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
