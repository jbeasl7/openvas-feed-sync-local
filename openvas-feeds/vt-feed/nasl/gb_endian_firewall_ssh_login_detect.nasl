# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105391");
  script_version("2026-05-08T06:16:21+0000");
  script_tag(name:"last_modification", value:"2026-05-08 06:16:21 +0000 (Fri, 08 May 2026)");
  script_tag(name:"creation_date", value:"2015-10-01 12:50:18 +0200 (Thu, 01 Oct 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Endian Firewall Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/endian/firewall/detected");

  script_tag(name:"summary", value:"SSH login-based detection of Endian Firewall");

  exit(0);
}

if (!port = get_kb_item("ssh/login/endian/firewall/port"))
  exit(0);

if (!rls = get_kb_item("ssh/login/endian/firewall/" + port + "/release"))
  exit(0);

version = "unknown";

set_kb_item(name: "endian/firewall/detected", value: TRUE);
set_kb_item(name: "endian/firewall/ssh-login/detected", value: TRUE);
set_kb_item(name: "endian/firewall/ssh-login/port", value: port);
set_kb_item(name: "endian/firewall/ssh-login/" + port + "/concluded", value: rls);

vers = eregmatch(pattern: 'Endian Firewall( Community)? release ([0-9]+\\.[^\r\n]+)', string: rls);
if (!isnull(vers[2]))
  version = vers[2];

set_kb_item(name: "endian/firewall/ssh-login/" + port + "/version", value: version);

exit(0);
