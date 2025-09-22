# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153005");
  script_version("2024-09-10T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-09-10 05:05:42 +0000 (Tue, 10 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-03 09:05:58 +0000 (Tue, 03 Sep 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Progress / Ipswitch WhatsUp Gold Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_progress_whatsup_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_progress_whatsup_smb_login_detect.nasl");
  script_mandatory_keys("progress/whatsup_gold/detected");

  script_tag(name:"summary", value:"Consolidation of Progress / Ipswitch WhatsUp Gold
  detections.");

  script_xref(name:"URL", value:"https://www.whatsupgold.com");

  exit(0);
}

if (!get_kb_item("progress/whatsup_gold/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("smb-login", "http")) {
  version_list = get_kb_list("progress/whatsup_gold/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:progress:whatsupgold:");
if (!cpe)
  cpe = "cpe:/a:progress:whatsupgold";

os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", runs_key: "windows",
                       desc: "Progress / Ipswitch WhatsUp Gold Detection Consolidation");

if (http_ports = get_kb_list("progress/whatsup_gold/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("progress/whatsup_gold/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("progress/whatsup_gold/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (!isnull(concl = get_kb_item("progress/whatsup_gold/smb-login/0/concluded"))) {
  extra += 'Local Detection via SMB login:\n\n';
  extra += concl + '\n';

  insloc = get_kb_item("progress/whatsup_gold/smb-login/0/location");
  if (insloc && insloc != "unknown") {
    extra += "Location:       " + insloc + '\n';
    register_product(cpe: cpe, location: insloc, port: 0, service: "smb-login");
  } else {
    register_product(cpe: cpe, location: location, port: 0, service: "smb-login");
  }
}

report  = build_detection_report(app: "Progress / Ipswitch WhatsUp Gold", version: detected_version,
                                 install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
