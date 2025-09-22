# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143679");
  script_version("2024-05-24T19:38:34+0000");
  script_tag(name:"last_modification", value:"2024-05-24 19:38:34 +0000 (Fri, 24 May 2024)");
  script_tag(name:"creation_date", value:"2020-04-08 02:12:28 +0000 (Wed, 08 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Huawei VRP Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh-login/huawei/vrp/detected");

  script_tag(name:"summary", value:"SSH login-based detection of Huawei Versatile Routing Platform
  (VRP) network devices.");

  exit(0);
}

if (!port = get_kb_item("ssh-login/huawei/vrp/port"))
  exit(0);

if (!display_version = get_kb_item("ssh-login/huawei/vrp/" + port + "/display_version"))
  exit(0);

if (!login_banner = get_kb_item("ssh-login/huawei/vrp/" + port + "/login_banner"))
  exit(0);

set_kb_item(name: "huawei/vrp/detected", value: TRUE);
set_kb_item(name: "huawei/vrp/ssh-login/" + port + "/detected", value: TRUE);
set_kb_item(name: "huawei/vrp/ssh-login/port", value: port);

model = "unknown";
version = "unknown";
patch_version = "unknown";
concluded = '\n  - Login banner:    ' + login_banner;

# HUAWEI S5735-S24T4X Routing Switch uptime
# HUAWEI NE05E-SQ uptime
# Huawei AP5030DN Router uptime
# HUAWEI S7703 Terabit Routing Switch uptime
#
# nb: Some devices seems to not support "display device" so we're first trying this one...
mod = eregmatch(pattern: "HUAWEI ([^ ]+) ((Terabit )?Routing Switch |Router )?uptime( is)?", string: display_version, icase: TRUE);
if (!isnull(mod[1])) {
  concluded += '\n  - Model:           ' + mod[0] + " (truncated)";
  model = mod[1];
}

# ... and falling back to display device if the extraction above failed.
if (model == "unknown") {
  display_device = get_kb_item("ssh-login/huawei/vrp/" + port + "/display_device");
  if (display_device) {

    # S7712's Device status:
    # S5735-S24T4X's Device status:
    # NE05E-SQ's Device status:
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

# VRP (R) software, Version 5.170 (S5735 V200R019C00SPC500)
# VRP (R) software, Version 8.190 (NE05E-SQ V300R005C10SPC100)
# VRP (R) software, Version 5.130 (AP5030DN FIT V200R010C00)
# VRP (R) software, Version 5.150 (S7700 V200R007C00SPC100)
vers = eregmatch(pattern: 'Version ([0-9.]+)[^\r\n]*(V[0-9A-Z]+)\\)', string: display_version);
if (!isnull(vers[2])) {
  version = vers[2];
  set_kb_item(name: "huawei/vrp/ssh-login/major_version", value: vers[1]);
  concluded += '\n  - Version:         ' + vers[0];
}

patch_info = get_kb_item("ssh-login/huawei/vrp/" + port + "/patch-information");

# Patch version    :    V200R010C00SPH
# Patch Package Version:V200R013SPH
# Patch Package Version :V300R005SPH022
# Patch version      :ARV200R009SPH021
pattern = "Patch (version|Package Version)\s*:.*(V[0-9A-Z]+)";
patch_line = egrep(pattern: pattern, string: patch_info, icase: TRUE);
patch_line = chomp(patch_line);
if (patch_line) {
  patch = eregmatch(pattern: pattern, string: patch_line, icase: TRUE);
  if (!isnull(patch[2])) {
    patch_version = patch[2];
    concluded += '\n  - Installed patch: ' + patch[2];
  }
} else if ("Info: No patch exists." >< patch_info) {
  patch_version = "No patch installed";
  concluded += '\n  - Installed patch: "Info: No patch exists."';
}

if (concluded)
  set_kb_item(name: "huawei/vrp/ssh-login/" + port + "/concluded", value: concluded);

set_kb_item(name: "huawei/vrp/ssh-login/" + port + "/model", value: model);
set_kb_item(name: "huawei/vrp/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "huawei/vrp/ssh-login/" + port + "/patch", value: patch_version);

exit(0);
