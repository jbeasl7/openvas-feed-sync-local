# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105407");
  script_version("2025-01-16T05:37:14+0000");
  script_tag(name:"last_modification", value:"2025-01-16 05:37:14 +0000 (Thu, 16 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-10-16 19:26:14 +0200 (Fri, 16 Oct 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Juniper Networks Junos Space Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/juniper/junos/space/detected");

  script_tag(name:"summary", value:"SSH login-based detection of Juniper Networks Junos Space.");

  exit(0);
}

if (!port = get_kb_item("ssh/login/juniper/junos/space/port"))
  exit(0);

rls = get_kb_item("ssh/login/juniper/junos/space/" + port + "/release");
if (!rls || rls !~ "Space release [0-9][0-9.]+([^0-9.][0-9.]+)? \((dev.)?[0-9]+\)")
  exit(0);

version = "unknown";
build = "unknown";

set_kb_item(name: "juniper/junos/space/detected", value: TRUE);
set_kb_item(name: "juniper/junos/space/ssh-login/detected", value: TRUE);
set_kb_item(name: "juniper/junos/space/ssh-login/port", value: port);
set_kb_item(name: "juniper/junos/space/ssh-login/" + port + "/concluded", value: rls);

# 12.3P2.8
# 15.1R1
vers = eregmatch(pattern: "Space release ([0-9][0-9.]+([^0-9.][0-9.]+)?) \((dev.)?([0-9]+)\)", string: rls);
if (!isnull(vers[1]))
  version = vers[1];

if (!isnull(vers[4]))
  build = vers[4];

set_kb_item(name: "juniper/junos/space/ssh-login/" + port + "/version", value: version);
set_kb_item(name: "juniper/junos/space/ssh-login/" + port + "/build", value: build);

exit(0);
