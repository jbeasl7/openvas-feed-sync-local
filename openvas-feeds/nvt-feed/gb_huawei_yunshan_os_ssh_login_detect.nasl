# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152274");
  script_version("2024-05-24T19:38:34+0000");
  script_tag(name:"last_modification", value:"2024-05-24 19:38:34 +0000 (Fri, 24 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-22 03:21:26 +0000 (Wed, 22 May 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Huawei YunShan OS Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh-login/huawei/yunshan_os/detected");

  script_tag(name:"summary", value:"SSH login-based detection of Huawei YunShan OS based network
  devices (including the underlying hardware device and it's version).");

  exit(0);
}

if (!port = get_kb_item("ssh-login/huawei/yunshan_os/port"))
  exit(0);

if (!display_version = get_kb_item("ssh-login/huawei/yunshan_os/" + port + "/display_version"))
  exit(0);

if (!login_banner = get_kb_item("ssh-login/huawei/yunshan_os/" + port + "/login_banner"))
  exit(0);

set_kb_item(name: "huawei/yunshan_os/detected", value: TRUE);
set_kb_item(name: "huawei/yunshan_os/ssh-login/" + port + "/detected", value: TRUE);
set_kb_item(name: "huawei/yunshan_os/ssh-login/port", value: port);

model = "unknown";
yunshan_os_version = "unknown";
device_version = "unknown";
device_patch_version = "unknown";
concluded = '\n  - Login banner:    ' + login_banner;

# nb: Some devices seems to not support "display device" so we're first trying this one...
mod = eregmatch(pattern: "HUAWEI ((CloudEngine )?[^ ]+) ((Terabit )?Routing Switch |Router )?uptime( is)?", string: display_version, icase: TRUE);
if (!isnull(mod[1])) {
  concluded += '\n  - Model:           ' + mod[0] + " (truncated)";
  model = mod[1];
}

# ... and falling back to display device if the extraction above failed.
if (model == "unknown") {
  display_device = get_kb_item("ssh-login/huawei/yunshan_os/" + port + "/display_device");
  if (display_device) {
    device = egrep(pattern: "(.+)'s Device status:", string: display_device, icase: FALSE);
    if (device) {
      mod = eregmatch(pattern: "(.+)'s Device status:", string: device, icase: FALSE);
      if (!isnull(mod[1])) {
        concluded += '\n  - Model:           ' + mod[0];
        model = mod[1];
      }
    }
  }
}

# Version 1.23.0.1 (AR5700 V600R023C00SPC100)
vers_info = eregmatch(pattern: 'Version ([0-9.]+)[^\r\n]*(V[0-9A-Z]+)\\)', string: display_version);
if (!isnull(vers_info[1])) {
  yunshan_os_version = vers_info[1];
  device_version = vers_info[2];

  # nb: As both "1.23.0.1" and "V600R023C00SPC100" are mandatory in the pattern above we don't need
  # an additional check here.

  concluded += '\n  - Versions:        ' + vers_info[0];
}

patch_info = get_kb_item("ssh-login/huawei/yunshan_os/" + port + "/patch-information");

pattern = "Patch (version|Package Version)\s*:.*(V[0-9A-Z]+)";
patch_line = egrep(pattern: pattern, string: patch_info, icase: TRUE);
patch_line = chomp(patch_line);
if (patch_line) {
  patch = eregmatch(pattern: pattern, string: patch_line, icase: TRUE);
  if (!isnull(patch[2])) {
    device_patch_version = patch[2];
    concluded += '\n  - Installed patch: ' + patch[2];
  }
} else if ("Info: No patch exists." >< patch_info) {
  device_patch_version = "No patch installed";
  concluded += '\n  - Installed patch: "Info: No patch exists."';
}

if (concluded)
  set_kb_item(name: "huawei/yunshan_os/ssh-login/" + port + "/concluded", value: concluded);

set_kb_item(name: "huawei/yunshan_os/ssh-login/" + port + "/model", value: model);
set_kb_item(name: "huawei/yunshan_os/ssh-login/" + port + "/yunshan_os_version", value: yunshan_os_version);
set_kb_item(name: "huawei/yunshan_os/ssh-login/" + port + "/device_version", value: device_version);
set_kb_item(name: "huawei/yunshan_os/ssh-login/" + port + "/device_patch_version", value: device_patch_version);

exit(0);
