# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153900");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-30 09:17:56 +0000 (Thu, 30 Jan 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Unraid OS Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/unraid/detected");

  script_tag(name:"summary", value:"SSH login-based detection of Unraid.");

  exit(0);
}

if (!port = get_kb_item("ssh/login/unraid/port"))
  exit(0);

version = "unknown";

set_kb_item(name: "unraid/detected", value: TRUE);
set_kb_item(name: "unraid/ssh-login/detected", value: TRUE);
set_kb_item(name: "unraid/ssh-login/port", value: port);

versinfo = get_kb_item("unraid/ssh-login/" + port + "/vers_info");
if (versinfo) {
  vers = eregmatch(pattern: 'version\\s*=\\s*"([0-9.]+)', string: versinfo);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "unraid/ssh-login/" + port + "/concluded", value: versinfo);
  }
}

set_kb_item(name: "unraid/ssh-login/" + port + "/version", value: version);

exit(0);
