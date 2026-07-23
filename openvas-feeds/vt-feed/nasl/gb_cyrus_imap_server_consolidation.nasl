# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.157463");
  script_version("2026-07-22T06:26:54+0000");
  script_tag(name:"last_modification", value:"2026-07-22 06:26:54 +0000 (Wed, 22 Jul 2026)");
  script_tag(name:"creation_date", value:"2026-07-20 08:50:25 +0000 (Mon, 20 Jul 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cyrus IMAP Server Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_cyrus_imap_server_imap_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_cyrus_imap_server_pop3_detect.nasl");
  script_mandatory_keys("cyrus/imap_server/detected");

  script_tag(name:"summary", value:"Consolidation of Cyrus IMAP Server detections.");

  script_xref(name:"URL", value:"https://www.cyrusimap.org/");

  exit(0);
}

if (!get_kb_item("cyrus/imap_server/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("imap", "pop3")) {
  version_list = get_kb_list("cyrus/imap_server/" + source + "/*/version");
  foreach version (version_list) {
    if (version !~ "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:cyrus:imap:");
if (!cpe)
  cpe = "cpe:/a:cyrus:imap";

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", runs_key: "unixoide",
                       desc: "Cyrus IMAP Server Detection Consolidation");

if (imap_ports = get_kb_list("cyrus/imap_server/imap/port")) {
  foreach port (imap_ports) {
    extra += "IMAP on port " + port + '\n';

    concluded = get_kb_item("cyrus/imap_server/imap/" + port + "/concluded");
    if (concluded)
      extra += "  IMAP Banner: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "imap");
  }
}

if (pop3_ports = get_kb_list("cyrus/imap_server/pop3/port")) {
  foreach port (pop3_ports) {
    extra += "POP3 on port " + port + '/tcp\n';

    concluded = get_kb_item("cyrus/imap_server/pop3/" + port + "/concluded");
    if (concluded)
      extra += "  POP3 Banner: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "pop3");
  }
}

report = build_detection_report(app: "Cyrus IMAP", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
