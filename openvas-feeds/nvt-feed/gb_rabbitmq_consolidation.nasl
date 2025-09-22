# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153539");
  script_version("2025-03-27T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-27 05:38:50 +0000 (Thu, 27 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-11-27 10:31:51 +0000 (Wed, 27 Nov 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RabbitMQ Server Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_rabbitmq_amqp_detect.nasl",
                      "gb_rabbitmq_http_detect.nasl");
  script_mandatory_keys("rabbitmq/detected");

  script_tag(name:"summary", value:"Consolidation of RabbitMQ Server detections.");

  script_xref(name:"URL", value:"https://www.rabbitmq.com/");

  exit(0);
}

if (!get_kb_item("rabbitmq/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

# nb: Currently only extracted via AMQP
foreach source (make_list("amqp")) {
  version_list = get_kb_list("rabbitmq/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:vmware:rabbitmq:");
if (!cpe)
  cpe = "cpe:/a:vmware:rabbitmq";

if (http_ports = get_kb_list("rabbitmq/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    conclUrl = get_kb_item("rabbitmq/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (amqp_ports = get_kb_list("rabbitmq/amqp/port")) {
  foreach port (amqp_ports) {
    extra += "AMQP on port " + port + '/tcp\n';

    concluded = get_kb_item("rabbitmq/amqp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "amqp");
  }
}

report  = build_detection_report(app: "RabbitMQ Server", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
