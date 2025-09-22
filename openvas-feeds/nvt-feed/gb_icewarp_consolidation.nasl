# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140330");
  script_version("2023-08-04T16:09:15+0000");
  script_tag(name:"last_modification", value:"2023-08-04 16:09:15 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-08-28 15:51:57 +0700 (Mon, 28 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IceWarp Mail Server Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_icewarp_http_detect.nasl", "gb_icewarp_pop3_detect.nasl",
                      "gb_icewarp_smtp_detect.nasl", "gb_icewarp_imap_detect.nasl");
  script_mandatory_keys("icewarp/mailserver/detected");

  script_tag(name:"summary", value:"Consolidation of IceWarp Mail Server detections.");

  script_xref(name:"URL", value:"https://www.icewarp.com/");

  exit(0);
}

if (!get_kb_item( "icewarp/mailserver/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("http", "pop3", "smtp", "imap")) {
  version_list = get_kb_list("icewarp/mailserver/" + source + "/*/version");
  foreach version (version_list) {
    detected_version = version;
    break;
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:icewarp:mail_server:");
if (!cpe)
  cpe = "cpe:/a:icewarp:mail_server";

if (http_ports = get_kb_list("icewarp/mailserver/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port: " + port + '/tcp\n';

    concluded = get_kb_item("icewarp/mailserver/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: \n' + concluded + '\n';

    conclUrl = get_kb_item("icewarp/mailserver/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location: \n' + conclUrl + '\n';

    # nb: Active checks are currently using "/webmail" hardcoded in their requests. If this install
    # variable is changed to be dynamic then make sure to update the active checks accordingly.
    register_product(cpe: cpe, location: "/webmail", port: port, service: "www");
  }
}

if (imap_ports = get_kb_list("icewarp/mailserver/imap/port")) {
  foreach port (imap_ports) {
    extra += "IMAP on port " + port + '/tcp\n';

    concluded = get_kb_item("icewarp/mailserver/imap/" + port + "/concluded");
    if (concluded)
      extra += "  IMAP Banner: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "imap");
  }
}

if (pop3_ports = get_kb_list("icewarp/mailserver/pop3/port")) {
  foreach port (pop3_ports) {
    extra += "POP3 on port " + port + '/tcp\n';

    concluded = get_kb_item("icewarp/mailserver/pop3/" + port + "/concluded");
    if (concluded)
      extra += "  POP3 Banner: " + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "pop3");
  }
}

if (smtp_ports = get_kb_list("icewarp/mailserver/smtp/port")) {
  foreach port (smtp_ports) {
    extra += "SMTP on port " + port + '/tcp\n';

    concluded = get_kb_item("icewarp/mailserver/smtp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: \n' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "smtp");
  }
}

report = build_detection_report(app: "IceWarp Mail Server", version: detected_version, install: location,
                                cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
