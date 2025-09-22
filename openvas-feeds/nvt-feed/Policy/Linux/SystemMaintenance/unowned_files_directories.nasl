# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109819");
  script_version("2022-09-13T10:15:09+0000");
  script_tag(name:"last_modification", value:"2022-09-13 10:15:09 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"creation_date", value:"2019-03-18 11:05:45 +0100 (Mon, 18 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Orphaned files or directories");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://linuxhandbook.com/linux-file-permissions/");
  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 6.1.11 Ensure no unowned files or directories exist (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 6.1.11 Ensure no unowned files or directories exist (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 13.2 Remove Sensitive Data or Systems Not Regularly Accessed by Organization");

  script_tag(name:"summary", value:"If any unowned file or directory exist on the host and a new
user is created, it could happen that the user gets the same UID as the unowned file or directory.
This user automatically becomes the owner of such files or directories.

This script tests if any orphaned file or directory exist on the host.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = 'df --local -P | awk {\'if ( NR!=1 ) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -nouser';
title = "Orphaned files or directories";
solution = "Locate files that are owned by users or groups not listed in the system configuration files,
and reset the ownership of these files to some active user on the system as appropriate.";
test_type = "SSH_Cmd";
default = "None";
comment = "";
value = "None";

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection";
}else if (!value = ssh_cmd(cmd:cmd, socket:sock, return_errors:TRUE, nosh:TRUE ) ) {
  compliant = "yes";
} else {
  compliant = "no";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);