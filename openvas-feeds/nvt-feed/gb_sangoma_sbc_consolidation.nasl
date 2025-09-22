# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152791");
  script_version("2024-08-02T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-08-02 05:05:39 +0000 (Fri, 02 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-01 05:15:44 +0000 (Thu, 01 Aug 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sangoma Session Border Controller (SBC) Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_sangoma_sbc_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_sangoma_sbc_ssh_detect.nasl");
  script_mandatory_keys("sangoma/sbc/detected");

  script_tag(name:"summary", value:"Consolidation of Sangoma Session Border Controller (SBC)
  detections.");

  script_xref(name:"URL", value:"https://sangoma.com/products-and-solutions/phones-and-hardware/products/voip-gateways/session-border-controllers/");

  exit(0);
}

if (!get_kb_item("sangoma/sbc/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("ssh", "http")) {
  version_list = get_kb_list("sangoma/sbc/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_name = "Sangoma Session Border Controller (SBC) Firmware";
hw_name = "Sangoma Session Border Controller (SBC)";

os_cpe = build_cpe(value: version, exp: "^([0-9.-]+)", base: "cpe:/o:sangoma:session_border_controller_firmware:");
if (!os_cpe)
  os_cpe = "cpe:/o:sangoma:session_border_controller_firmware";

hw_cpe = "cpe:/h:sangoma:session_border_controller";

os_register_and_report(os: os_name, cpe: os_cpe, runs_key: "unixoide",
                       desc: "Sangoma Session Border Controller (SBC) Detection Consolidation");

if (http_ports = get_kb_list("sangoma/sbc/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("sangoma/sbc/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("sangoma/sbc/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (ssh_ports = get_kb_list("sangoma/sbc/ssh/port")) {
  foreach port (ssh_ports) {
    extra += "SSH on port " + port + '/tcp\n';

    concluded = get_kb_item("sangoma/sbc/ssh/" + port + "/concluded");
    if (concluded)
      extra += "  SSH Login Banner: " + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "ssh");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ssh");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
