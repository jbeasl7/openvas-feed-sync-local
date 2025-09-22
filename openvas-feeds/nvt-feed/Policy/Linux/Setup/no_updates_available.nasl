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
  script_oid("1.3.6.1.4.1.25623.1.0.109750");
  script_version("2021-10-11T10:26:27+0000");
  script_tag(name:"last_modification", value:"2021-10-11 10:26:27 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"creation_date", value:"2019-01-18 09:31:06 +0100 (Fri, 18 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Package updates available");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 1.8 Ensure updates patches and additional security software are installed (Not Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 1.9 Ensure updates and patches and additional security software are installed (Not Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 3.5 Deploy Automated Software Patch Management Tools");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 3.4 Deploy Automated Operating System Patch Management Tools");

  script_tag(name:"summary", value:"Package updates may include vulnerability fixes or new
functionality to a package. Keeping the packages to the newest available version reduces the risk of
a successful attack.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "yum check-update,apt-get -s upgrade,zypper list-updates";
title = "Package updates available";
solution = "Update the system";
test_type = "SSH_Cmd";
default = "no";

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  compliant = "incomplete";
  value = "Error";
  comment = "No SSH connection to host";
}else{
  update_cmds = policy_build_list_from_string(str:cmd);
  foreach update_cmd (update_cmds){
    updates = ssh_cmd(socket:sock, cmd:update_cmd, return_errors:FALSE);
    if(updates){
      if("yum" >< cmd){
        value_split = split(updates, keep:FALSE);
        if(max_index(value_split)>1){
          value = "yes";
        }else{
          value = "no";
        }
      }else if("apt-get" >< cmd){
        if(updates =~ "0\s+upgraded"){
          value = "no";
        }else{
          value = "yes";
        }
      }else if("zypper" >< cmd){
        if(updates =~ "no\s+updates\s+found"){
          value = "no";
        }else{
          value = "yes";
        }
      }
      break;
    }
  }

  if(!value){
    compliant = "incomplete";
    value = "Error";
    comment = "Host did not recognize yum, apt-get or zypper";
  }else{
    compliant = policy_setting_exact_match(value:value, set_point:default);
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
