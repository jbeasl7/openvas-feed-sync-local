# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152275");
  script_version("2024-05-24T19:38:34+0000");
  script_tag(name:"last_modification", value:"2024-05-24 19:38:34 +0000 (Fri, 24 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-22 03:31:16 +0000 (Wed, 22 May 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei YunShan OS Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_huawei_yunshan_os_ssh_login_detect.nasl");
  script_mandatory_keys("huawei/yunshan_os/detected");

  script_tag(name:"summary", value:"Consolidation of Huawei YunShan OS based network devices
  (including the underlying hardware device and it's version) detections.");

  script_xref(name:"URL", value:"http://e.huawei.com/en/");

  exit(0);
}

if (!get_kb_item("huawei/yunshan_os/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("huawei.inc");

set_kb_item(name: "huawei/data_communication_product/detected", value: TRUE);

detected_yunshan_os_version = "unknown";
detected_model = "unknown";
detected_device_version = "unknown";
detected_device_patch_version = "unknown";
location = "/";

foreach source (make_list("ssh-login")) {
  device_version_list = get_kb_list("huawei/yunshan_os/" + source + "/*/device_version");
  foreach device_version (device_version_list) {
    if (device_version != "unknown" && detected_device_version == "unknown") {
      detected_device_version = device_version;
      set_kb_item(name: "huawei/yunshan_os/device_version", value: detected_device_version);
      break;
    }
  }

  model_list = get_kb_list("huawei/yunshan_os/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "huawei/yunshan_os/model", value: detected_model);
      break;
    }
  }

  yunshan_os_version_list = get_kb_list("huawei/yunshan_os/" + source + "/*/yunshan_os_version");
  foreach yunshan_os_version (yunshan_os_version_list) {
    if (yunshan_os_version != "unknown" && detected_yunshan_os_version == "unknown") {
      detected_yunshan_os_version = yunshan_os_version;
      set_kb_item(name: "huawei/yunshan_os/yunshan_os_version", value: detected_yunshan_os_version);
      break;
    }
  }

  if (detected_device_version != "unknown" && detected_model != "unknown" && detected_yunshan_os_version != "unknown")
    break;
}

os_name_1 = "Huawei YunShan OS";
os_cpe_1 = build_cpe(value: tolower(detected_yunshan_os_version), exp: "^([0-9.]+)", base: "cpe:/o:huawei:yunshan_os:");
if (!os_cpe_1)
  os_cpe_1 = "cpe:/o:huawei:yunshan_os";

os_register_and_report(os: os_name_1, cpe: os_cpe_1, desc: "Huawei YunShan OS Detection Consolidation",
                       version: detected_yunshan_os_version, full_cpe: TRUE, runs_key: "unixoide");

if (detected_model != "unknown") {
  hw_name = "Huawei " + detected_model + " Network Device";
  hw_cpe = "cpe:/h:huawei:" + tolower(detected_model);
  hw_cpe = str_replace(string: hw_cpe, find: " ", replace: "_");
  os_name_2 = "Huawei " + detected_model + " Network Device Firmware";
  os_cpe_2 = "cpe:/o:huawei:" + tolower(detected_model) + "_firmware";
  os_cpe_2 = str_replace(string: os_cpe_2, find: " ", replace: "_");
} else {
  hw_name = "Huawei Unknown Model Network Device";
  hw_cpe = "cpe:/h:huawei:network_device";
  os_name_2 = "Huawei Unknown Model Network Device Firmware";
  os_cpe_2 = "cpe:/o:huawei:network_device_firmware";
}

if (detected_device_version != "unknown")
  os_cpe_2 += ":" + tolower(detected_device_version);

# Add more generic CPE matching the CPEs from Huawei Security Advisories (SA).
# For example we're detecting S5735-S24T4X above but need to set an additional
# generic "cpe:/o:huawei:s5700_firmware" CPE.
huawei_sa_cpe = huawei_find_device(cpe_string: os_cpe_2);

os_register_and_report(os: os_name_2, cpe: os_cpe_2, desc: "Huawei YunShan OS Detection Consolidation",
                       version: detected_device_version, full_cpe: TRUE, runs_key: "unixoide");

if (ssh_login_ports = get_kb_list("huawei/yunshan_os/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra = "SSH login on port " + port + '/tcp\n';

    concluded = get_kb_item("huawei/yunshan_os/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result:" + concluded + '\n';

    # nb: This is passed from gather-package-list.nasl and thus has a different prefix in the KB key
    concluded_command = get_kb_item("ssh-login/huawei/yunshan_os/" + port + "/concluded_command");
    if (concluded_command)
      extra += "  Concluded from version/product identification command(s):" + concluded_command + '\n';

    device_patch_version = get_kb_item("huawei/yunshan_os/ssh-login/" + port + "/device_patch_version");
    if (device_patch_version) {
      detected_device_patch_version = device_patch_version;

      if (detected_device_patch_version != "No patch installed")
        set_kb_item(name: "huawei/yunshan_os/device_patch_version", value: detected_device_patch_version);
    }

    register_product(cpe: os_cpe_1, location: location, port: port, service: "ssh-login");
    register_product(cpe: os_cpe_2, location: location, port: port, service: "ssh-login");
    register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
    if (huawei_sa_cpe)
      register_product(cpe: huawei_sa_cpe, location: location, port: port, service: "ssh-login");
  }
}

patch_nd_cpe_extra = "  Patch Version: " + detected_device_patch_version;
if (huawei_sa_cpe)
  patch_nd_cpe_extra += '\n  Additional CPE registered: ' + huawei_sa_cpe;

report = build_detection_report(app: os_name_1, version: detected_yunshan_os_version, install: location, cpe: os_cpe_1);
report += '\n\n';

report += build_detection_report(app: os_name_2, version: detected_device_version, install: location, cpe: os_cpe_2,
                                 extra: patch_nd_cpe_extra );
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
