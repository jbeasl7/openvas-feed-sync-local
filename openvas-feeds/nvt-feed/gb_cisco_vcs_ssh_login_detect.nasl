# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105804");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-02-21T14:36:44+0000");
  script_tag(name:"last_modification", value:"2024-02-21 14:36:44 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-07-11 11:45:51 +0200 (Mon, 11 Jul 2016)");

  script_tag(name:"qod_type", value:"package");

  script_name("Cisco TelePresence Video Communication Server (VCS) Detection (SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco/ssh/expressway", "cisco/ssh/expressway/uname");

  script_tag(name:"summary", value:"SSH login based detection of Cisco TelePresence Video
  Communication Server (VCS).");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if (!get_kb_item("cisco/ssh/expressway"))
  exit(0);

port = kb_ssh_transport();

if (!soc = ssh_login_or_reuse_connection())
  exit(0);

uname = get_kb_item("cisco/ssh/expressway/uname");
if (!uname || "TANDBERG Video Communication Server X" >!< uname)
  exit(0);

xstatus = ssh_cmd(socket: soc, cmd: "xstatus SystemUnit", return_errors: TRUE, nosh: TRUE, pty: TRUE, timeout: 20,
                  retry: 20, pattern: '\\*s/end[\r\n]+OK');

# ExpresswaySeries: "False"
if (!xstatus || xstatus !~ 'ExpresswaySeries\\s*:\\s*"False"')
  exit(0);

version = "unknown";

vers = eregmatch(pattern: "TANDBERG Video Communication Server X([0-9.]+)", string: uname);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "cisco/vcs/ssh-login/" + port + "/concluded", value: vers[0]);
}

set_kb_item(name: "cisco/vcs/detected", value: TRUE);
set_kb_item(name: "cisco/vcs/ssh-login/detected", value: TRUE);
set_kb_item(name: "cisco/vcs/ssh-login/port", value: port);
set_kb_item(name: "cisco/vcs/ssh-login/" + port + "/concluded", value: vers[0]);

set_kb_item(name: "cisco/vcs/ssh-login/" + port + "/version", value: version);

exit(0);
