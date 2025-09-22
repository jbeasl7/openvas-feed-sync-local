# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105433");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-11-06 12:16:22 +0100 (Fri, 06 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Cisco Content Security Management (CSM) Appliance Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_csma_http_detect.nasl", "gather-package-list.nasl");
  script_mandatory_keys("cisco_csm/detected");

  script_tag(name:"summary", value:"Consolidation of Cisco Content Security Management (CSM)
  Appliance detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");

if(!get_kb_item("cisco_csm/detected"))
  exit(0);

detected_model   = "unknown";
detected_version = "unknown";

foreach source(make_list("http", "ssh-login")) {
  model_list = get_kb_list("cisco_csm/" + source + "/*/model");
  foreach model(model_list) {
    if(model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name:"cisco_csm/model", value:detected_model);
    }
  }

  vers_list = get_kb_list("cisco_csm/" + source + "/*/version");
  foreach vers(vers_list) {
    if(vers != "unknown" && detected_version == "unknown") {
      detected_version = vers;
      set_kb_item(name:"cisco_csm/version", value:detected_version);
    }
  }
}

os_register_and_report(os:"Cisco AsyncOS", cpe:"cpe:/o:cisco:asyncos", desc:"Cisco Content Security Management (CSM) Appliance Detection Consolidation", runs_key:"unixoide");

app_name = "Cisco Content Security Management Appliance";
if(detected_model != "unknown")
  app_name += " " + detected_model;

cpe = "cpe:/a:cisco:content_security_management_appliance";
if(detected_version != "unknown")
  cpe += ":" + detected_version;

location = "/";
extra = "";

if(http_ports = get_kb_list("cisco_csm/http/port")) {
  foreach port(http_ports) {
    if(extra)
      extra += '\n';
    extra += 'HTTP(s) on port ' + port + '/tcp\n';
    concl = get_kb_item("cisco_csm/http/" + port + "/concluded");
    if(concl)
      extra += '  Concluded from:\n' + concl + '\n';

    register_product(cpe:cpe, location:location, port:port, service:"www");
  }
}

if(ssh_ports = get_kb_list("cisco_csm/ssh-login/port")) {
  foreach port(ssh_ports) {
    if(extra)
      extra += '\n';
    extra += 'SSH login on port ' + port + '/tcp\n';
    concluded = get_kb_item("cisco_csm/ssh-login/" + port + "/concluded");
    if(concluded)
      extra += '  Concluded from "version" SSH command response:\n' + concluded + '\n';

    register_product(cpe:cpe, location:location, port:port, service:"ssh-login");
  }
}

report = build_detection_report(app: app_name, version: detected_version, install: location, cpe: cpe);
if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
