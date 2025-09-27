# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105612");
  script_version("2025-09-26T15:41:32+0000");
  script_tag(name:"last_modification", value:"2025-09-26 15:41:32 +0000 (Fri, 26 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-04-20 15:22:13 +0200 (Wed, 20 Apr 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Cisco Prime Infrastructure (PIS) Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/cisco/pis/show_ver");

  script_tag(name:"summary", value:"SSH login based detection of Cisco Prime Infrastructure
  (PIS).");

  exit(0);
}

include("version_func.inc");

if (!system = get_kb_item("ssh/login/cisco/pis/show_ver"))
  exit(0);

if (!port = get_kb_item("ssh/login/cisco/pis/port"))
  exit(0);

if ("Cisco Prime Infrastructure" >!< system)
  exit(0);

set_kb_item(name: "cisco/pis/detected", value: TRUE);
set_kb_item(name: "cisco/pis/ssh-login/detected", value: TRUE);
set_kb_item(name: "cisco/pis/ssh-login/port", value: port);
set_kb_item(name: "cisco/pis/ssh-login/" + port + "/concluded", value: system);

version = "unknown";
build = "unknown";

# Cisco Application Deployment Engine OS Release: 2.3
# ADE-OS Build Version: 2.3.0.101-root
# ADE-OS System Architecture: x86_64
#
# Hostname: cpi
#
#
# Version information of installed applications
# ---------------------------------------------
#
# Cisco Prime Infrastructure
# ********************************************************
# Version : 3.0.0
# Build : 3.0.0.0.78
# Critical Fixes:
#         PI 3.0.3 ( 3.0.0 )
# Prime Add-Ons:
#         Prime Insight Agent ( 1.0.0 )

lines = split(system);
foreach line (lines) {
  system -= line;
  if ("Cisco Prime Infrastructure" >< line)
    break;
}

vers = eregmatch(pattern: "Version\s*:\s*([0-9.]+)", string: system);
if (!isnull(vers[1]))
  version = vers[1];

bld = eregmatch(pattern: "Build\s*:\s*([0-9.]+)", string: system);
if (!isnull(bld[1]))
  build =  bld[1];

if ("Critical Fixes:" >< system) {
  lines = split(system);
  foreach line (lines) {
    system -= line;
    if ("Critical Fixes:" >< line)
      break;
  }

  lines = split(system);
  foreach line (lines) {
    if ("TECH PACK" >< line)
      continue;

    if (line =~ "PI [0-9]+") {
      patch = eregmatch(pattern: 'PI ([0-9]+[^ \r\n(]+) ', string: line);
      if (!isnull(patch[1])) {
        installed_patches += "PI " + patch[1] + '\n';

        if ("Update" >< patch[1]) {
          up = eregmatch(pattern: "(^[0-9.]+ )", string: patch[1]);
          if (!isnull(up[1]))
            patch[1] = up[1];
        }

        if (!max_patch_version )
          max_patch_version = patch[1];
        else
          if (version_is_less(version: max_patch_version, test_version: patch[1]))
            max_patch_version = patch[1];
      }
    } else
      break;
  }
}

if (max_patch_version) {
  set_kb_item(name: "cisco/pis/ssh-login/" + port + "/max_patch_version", value: max_patch_version);
  version = max_patch_version;
} else {
  set_kb_item(name: "cisco/pis/ssh-login/" + port + "/max_patch_version", value: "0");
}

if (installed_patches)
  set_kb_item(name: "cisco/pis/ssh-login/" + port + "/installed_patches", value: installed_patches);

set_kb_item(name: "cisco/pis/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "cisco/pis/ssh-login/" + port + "/build", value: build);

exit(0);
