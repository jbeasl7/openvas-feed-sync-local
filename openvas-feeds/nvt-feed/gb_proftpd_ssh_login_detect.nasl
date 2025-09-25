# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900506");
  script_version("2025-09-24T05:39:03+0000");
  script_tag(name:"last_modification", value:"2025-09-24 05:39:03 +0000 (Wed, 24 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("ProFTPD Detection (Linux/Unix SSH Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of ProFTPD Server.");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if (!sock = ssh_login_or_reuse_connection())
  exit(0);

port = kb_ssh_transport();

path_list = ssh_find_file(file_name: "/proftpd$", useregex: TRUE, sock: sock);
if (!path_list) {
  ssh_close_connection();
  exit(0);
}

foreach path (path_list) {
  if (!path = chomp(path))
    continue;

  cmd = path + " -v";

  vers = ssh_get_bin_version(full_prog_name: cmd, ver_pattern: "ProFTPD Version ([0-9.a-z]+)", sock: sock);
  if (!isnull(vers[1])) {
    concluded = vers[0];
    version = vers[1];

    set_kb_item(name: "proftpd/detected", value: TRUE);
    set_kb_item(name: "proftpd/ssh-login/detected", value: TRUE);
    set_kb_item(name: "proftpd/ssh-login/port", value: port);
    set_kb_item(name: "proftpd/ssh-login/" + port + "/concludedCmd", value: cmd);
    set_kb_item(name: "proftpd/ssh-login/" + port + "/concluded", value: concluded);
    set_kb_item(name: "proftpd/ssh-login/" + port + "/version", value: version);
  }
}

exit(0);
