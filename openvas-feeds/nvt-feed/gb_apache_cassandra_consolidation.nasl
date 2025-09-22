# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153930");
  script_version("2025-02-06T05:38:57+0000");
  script_tag(name:"last_modification", value:"2025-02-06 05:38:57 +0000 (Thu, 06 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-04 04:09:39 +0000 (Tue, 04 Feb 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache Cassandra Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_apache_cassandra_thrift_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_apache_cassandra_cql_detect.nasl");
  script_mandatory_keys("apache/cassandra/detected");

  script_tag(name:"summary", value:"Consolidation of Apache Cassandra detections.");

  script_xref(name:"URL", value:"https://cassandra.apache.org");

  exit(0);
}

if (!get_kb_item("apache/cassandra/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("thrift", "cql")) {
  version_list = get_kb_list("apache/cassandra/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:apache:cassandra:");
if (!cpe)
  cpe = "cpe:/a:apache:cassandra";

if (thrift_ports = get_kb_list("apache/cassandra/thrift/port")) {
  foreach port (thrift_ports) {
    extra += "Thrift on port " + port + '/tcp\n';

    concluded = get_kb_item("apache/cassandra/thrift/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: \n' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "thrift");
  }
}

if (cql_ports = get_kb_list("apache/cassandra/cql/port")) {
  foreach port (cql_ports) {
    extra += "CQL on port " + port + '/tcp\n';

    concluded = get_kb_item("apache/cassandra/cql/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: \n' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "cql");
  }
}

report  = build_detection_report(app: "Apache Cassandra", version: detected_version, install: location,
                                 cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
