# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152807");
  script_version("2024-08-06T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-08-06 05:05:45 +0000 (Tue, 06 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-05 05:02:27 +0000 (Mon, 05 Aug 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IBM Storwize / FlashSystem Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_ibm_storwize_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_ibm_storwize_slp_tcp_detect.nasl",
                        "gsf/gb_ibm_storwize_slp_udp_detect.nasl");
  script_mandatory_keys("ibm/storwize/detected");

  script_tag(name:"summary", value:"Consolidation of IBM Storwize / FlashSystem detections.");

  script_xref(name:"URL", value:"https://www.ibm.com/flashsystem");

  exit(0);
}

if (!get_kb_item("ibm/storwize/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
location = "/";

foreach source (make_list("openslp", "http")) {
  model_list = get_kb_list("ibm/storwize/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "ibm/storwize/model", value: detected_model);
      break;
    }
  }

  version_list = get_kb_list("ibm/storwize/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", runs_key: "unixoide",
                       desc: "IBM Storwize / FlashSystem Detection Consolidation");

if (detected_model != "unknown") {
  app_name = "IBM Storwize / FlashSystem " + detected_model + " Software";

  cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                  base: "cpe:/a:ibm:storage_virtualize:");
  if (!cpe)
    cpe = "cpe:/a:ibm:storage_virtualize";
} else {
  app_name = "IBM Storwize / FlashSystem Software";

  cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:storage_virtualize:");
  if (!cpe)
    cpe = "cpe:/a:ibm:storage_virtualize";
}

if (http_ports = get_kb_list("ibm/storwize/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("ibm/storwize/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    conclUrl = get_kb_item("ibm/storwize/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += "  Concluded from version/product identification location: " + conclUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (slp_ports = get_kb_list("ibm/storwize/openslp/port")) {
  foreach port (slp_ports) {
    slp_protos = get_kb_list("ibm/storwize/openslp/" + port + "/proto");
    foreach proto (slp_protos) {
      extra += "OpenSLP on port " + port + "/" + proto + '\n';

      concluded = get_kb_item("ibm/storwize/openslp/" + port + "/" + proto + "/concluded");
      if (concluded)
        extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

      register_product(cpe: cpe, location: location, port: port, service: "slp", proto: proto);
    }
  }
}

report = build_detection_report(app: app_name, version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
