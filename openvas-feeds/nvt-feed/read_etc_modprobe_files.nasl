# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150110");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-01-29 15:55:47 +0100 (Wed, 29 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Read files in /etc/modprobe.d/ (KB)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("gb_gnu_bash_detect_lin.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://linux.die.net/man/5/modprobe.d");

  script_tag(name:"summary", value:"Because the modprobe command can add or remove more than one
module, due to module dependencies, we need a method of specifying what options are to be used with
those modules. All files underneath the /etc/modprobe.d directory which end with the .conf extension
specify those options as required.

Note: This script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

files = "/etc/modprobe.d";

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/linux/" + files + "/ERROR", value:TRUE);
  exit(0);
}

if (!get_kb_item("bash/linux/detected")){
  set_kb_item(name:"Policy/linux/" + files + "/NO_BASH", value:TRUE);
  exit(0);
}

cmd = "find /etc/modprobe.d/ -type f -iname '*.conf'";
get_file_list = ssh_cmd(socket:sock, cmd:cmd, nosh:TRUE);

foreach file (split(get_file_list, keep:FALSE)){
  set_kb_item(name:"Policy/linux/" + files, value:file);
  policy_linux_stat_file(socket:sock, file:file);
  policy_linux_file_content(socket:sock, file:file);
}

exit(0);