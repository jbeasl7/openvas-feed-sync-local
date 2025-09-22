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
  script_oid("1.3.6.1.4.1.25623.1.0.109831");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2019-03-25 10:25:30 +0100 (Mon, 25 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: All GID in /etc/passwd match groups in /etc/group");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "policy_linux_file_content.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 6.2.15 Ensure all groups in /etc/passwd exist in /etc/group (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 6.2.14 Ensure all groups in /etc/passwd exist in /etc/group (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 16 Account Monitoring and Control");

  script_tag(name:"summary", value:"If groups appear in '/etc/passwd' but not in '/etc/group', group
permissions are not managed well. This can happen due to many changes over the time.

This script tests, if each GID listed in '/etc/passwd' match a group in '/etc/group'.");
  exit(0);
}

include( "policy_functions.inc" );
include( "list_array_func.inc" );

cmd = 'for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  grep -q -P "^.*?:[^:]*:$i:" /etc/group
  if [ $? -ne 0 ]; then
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
  fi
done';
title = "All groups in /etc/passwd exist in /etc/group";
solution = "Analyze the output of the Audit step above and perform the appropriate action to correct
any discrepancies found.";
test_type = "SSH_Cmd";
default = "None";

if( get_kb_item( "policy/linux/file_content/error" ) ) {
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
} else if( ! passwd = get_kb_item( "Policy/linux//etc/passwd/content" ) ) {
  value = "Error";
  compliant = "incomplete";
  comment = "Could not get content of '/etc/passwd'";
} else if( ! group = get_kb_item( "Policy/linux//etc/group/content" ) ) {
  value = "Error";
  compliant = "incomplete";
  comment = "Could not get content of '/etc/group'";
} else {
  group_gids = make_list();

  foreach line( split( group, keep:FALSE ) ) {
    fields = split( line, sep:":", keep:FALSE );
    if( ! fields )
      continue;

    group_gids = make_list( group_gids, fields[2] );
  }

  foreach line( split( passwd, keep:FALSE ) ) {
    fields = split( line, sep:":", keep:FALSE );
    if( ! fields )
      continue;

    if( ! in_array( search:fields[3], array:group_gids, part_match:FALSE, icase:FALSE ) ) {
      value += "Group " + fields[3] + " is referenced by /etc/passwd but does not exist in /etc/group" + '\n';
    }
  }

  if( ! value ) {
    compliant = "yes";
    value = "None";
  } else {
    compliant = "no";
    value = chomp(value);
  }
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );