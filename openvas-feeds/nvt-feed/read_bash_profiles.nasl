# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150099");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-01-22 16:06:28 +0100 (Wed, 22 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Read Shell Initialization files (KB)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://www.tecmint.com/understanding-shell-initialization-files-and-user-profiles-linux/");

  script_tag(name:"summary", value:"When the shell is invoked, there are certain initialization/startup
files it reads which help to setup an environment for the shell itself and the system user. That is
predefined (and customized) functions, variables, aliases and so on.

(C) Aaron Kili, 2017.

Files to consider: /etc/profile, /etc/bashrc, /etc/bash.bashrc, /etc/profile.d/*.sh.

Note: This script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success")){
  set_kb_item(name:"Policy/linux/shell_initialization/ERROR", value:TRUE);
  exit(0);
}

sock = ssh_login_or_reuse_connection();
if(!sock){
  set_kb_item(name:"Policy/linux/shell_initialization/ERROR", value:TRUE);
  exit(0);
}

profile_d_files =  ssh_find_file(file_name:"/etc/profile\.d/.+\.sh", useregex:TRUE, sock:sock);
shell_initialization_files = make_list("/etc/profile", "/etc/bashrc", "/etc/bash.bashrc", profile_d_files);

foreach file (shell_initialization_files){
  file = chomp(file);
  cmd = "cat " + file + " 2>/dev/null";
  # Some shell initialization files have "command not found" definition in file, which is assumed as error.
  # Thus: Return errors: TRUE to prevent this.
  content = ssh_cmd(socket:sock, cmd:cmd, return_errors:TRUE);
  if(content)
    set_kb_item(name:"Policy/linux/shell_initialization" + file, value:content);
  else
    set_kb_item(name:"Policy/linux/shell_initialization" + file + "/ERROR", value:TRUE);
}

exit(0);