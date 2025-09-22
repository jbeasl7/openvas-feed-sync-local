# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152955");
  script_version("2024-08-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-08-28 05:05:33 +0000 (Wed, 28 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-26 02:30:46 +0000 (Mon, 26 Aug 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Synology NAS / DiskStation Manager Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/synology/dsm/detected");

  script_tag(name:"summary", value:"SSH login-based detection of Synology NAS / DiskStation Manager
  (DSM).");

  exit(0);
}

if (!get_kb_item("ssh/login/synology/dsm/detected"))
  exit(0);

if (!port = get_kb_item("ssh/login/synology/dsm/port"))
  exit(0);

if (!version_info = get_kb_item("ssh/login/synology/dsm/" + port + "/version_info"))
  exit(0);

version = "unknown";
model = "unknown";

set_kb_item(name: "synology/dsm/detected", value: TRUE);
set_kb_item(name: "synology/dsm/ssh-login/detected", value: TRUE);
set_kb_item(name: "synology/dsm/ssh-login/port", value: port);
set_kb_item(name: "synology/dsm/ssh-login/" + port + "/concludedVers", value: version_info);

vers = eregmatch(pattern: 'productversion\\s*=\\s*"([0-9.]+)"', string: version_info);
if (!isnull) {
  version = vers[1];

  build = eregmatch(pattern: 'buildnumber\\s*=\\s*"([0-9]+)"', string: version_info);
  if (!isnull(build[1])) {
    version += "-" + build[1];

    fix = eregmatch(pattern: 'smallfixnumber\\s*=\\s*"([0-9]+)"', string: version_info);
    if (!isnull(fix[1]))
      version += "-" + fix[1];
  }
}

if (mod_info = get_kb_item("ssh/login/synology/dsm/" + port + "/model_info")) {
  mod = eregmatch(pattern: "syno_hw_version\s*=\s*([^ ]+)", string: mod_info);
  if (!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name: "synology/dsm/ssh-login/" + port + "/concludedMod", value: mod_info);
  }
}

set_kb_item(name: "synology/dsm/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "synology/dsm/ssh-login/" + port + "/model", value: model);

exit(0);
