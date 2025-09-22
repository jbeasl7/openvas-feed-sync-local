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
  script_oid("1.3.6.1.4.1.25623.1.0.109810");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2019-03-15 13:11:10 +0100 (Fri, 15 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Access /etc/passwd");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "policy_linux_file_permission.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Uid", type:"entry", value:"root", id:1);
  script_add_preference(name:"Gid", type:"entry", value:"root", id:2);
  script_add_preference(name:"Permissions", type:"entry", value:"644", id:3);

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 6.1.2 Ensure permissions on /etc/passwd are configured (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 6.1.2 Ensure permissions on /etc/passwd are configured (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 16.4 Encrypt or Hash all Authentication Credentials");

  script_tag(name:"summary", value:"The text file '/etc/passwd' contains essential information, which
is e.g. used during login. These information are used by many system utilities, thus read access is
required for these utilities to operate. File permissions for '/etc/passwd' can change during or
after an attack or other malicious actions.
This script checks if the given access rights are set on '/etc/passwd'.");
  exit(0);
}

include("policy_functions.inc");

cmd = "stat /etc/passwd";
title = "Permissions on /etc/passwd";
solution = "Run the following command to set permissions on /etc/passwd:
# chown root:root /etc/passwd
# chmod 644 /etc/passwd";
test_type = "SSH_Cmd";
default_uid = script_get_preference("Uid", id:1);
default_gid = script_get_preference("Gid", id:2);
default_perm = script_get_preference("Permissions", id:3);
default = "Uid:" + default_uid + ";Gid:" + default_gid + ";Permissions:" + default_perm;

if(get_kb_item("policy/linux/access_permissions/error")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/passwd";
}else{
  uid = get_kb_item("Policy/linux//etc/passwd/user");
  gid = get_kb_item("Policy/linux//etc/passwd/group");
  perm = get_kb_item("Policy/linux//etc/passwd/perm");

  if(!uid || !gid || !perm){
    value = "Error";
    compliant = "incomplete";
    comment = "Can not get access permissions on file";
  }else if((default_uid != uid && default_uid != "Ignore_Preference") ||
           (default_gid != gid && default_gid != "Ignore_Preference") ||
           (policy_access_permissions_match_or_stricter(value:perm, set_point:default_perm) != "yes" && default_perm != "Ignore_Preference")){
    compliant = "no";
  }else{
    compliant = "yes";
  }

  value = "Uid:" + uid + ";Gid:" + gid + ";Permissions:" + perm;
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);