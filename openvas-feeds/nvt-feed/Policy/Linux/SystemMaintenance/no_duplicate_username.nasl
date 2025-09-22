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
  script_oid("1.3.6.1.4.1.25623.1.0.109834");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2019-03-26 10:35:08 +0100 (Tue, 26 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Duplicated user names");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "policy_linux_file_content.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 6.2.18 Ensure no duplicate user names exist (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 6.2.17 Ensure no duplicate user names exist (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 16 Account Monitoring and Control");

  script_tag(name:"summary", value:"Duplicated user names can be created with modify '/etc/passwd'.
When logging in, the first found UID is used for that user leading to a shared UID.

This script tests if duplicated user names are listed in '/etc/passwd'.");

  exit(0);
}

include("policy_functions.inc");
include("list_array_func.inc");

cmd = 'cut -f1 -d":" /etc/passwd | sort -n | uniq -c | while read x ; do
  [ -z "$x" ] && break
  set - $x
  if [ $1 -gt 1 ]; then
    uids=$(awk -F: \'($1 == n) { print $3 }\' n=$2 /etc/passwd | xargs)
    echo "Duplicate User Name ($2)"
  fi
done';
title = "No duplicate user names";
solution = "Based on the results of the audit script, establish unique user names for the users. File
ownerships will automatically reflect the change as long as the users have unique UIDs.";
test_type = "SSH_Cmd";
default = "None";

if(get_kb_item("policy/linux/file_content/error")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(!content = get_kb_item("Policy/linux//etc/passwd/content")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/passwd";
}else{
  user_names = make_list();

  foreach line (split(content, keep:FALSE)){
    fields = split(line, sep:":", keep:FALSE);
    user = fields[0];
    if(!in_array(search:user, array:user_names, part_match:FALSE, icase:FALSE)){
      user_names = make_list(user_names, user);
    }else{
      value = "Duplicate User Name " + user + '\n';
    }
  }

  if(value){
    value = chomp(value);
    compliant = "no";
  }else{
    value = "None";
    compliant = "yes";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);