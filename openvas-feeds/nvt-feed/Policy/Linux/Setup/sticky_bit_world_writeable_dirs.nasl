# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109729");
  script_version("2023-09-22T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-09-22 05:05:30 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"creation_date", value:"2019-01-09 08:27:42 +0100 (Wed, 09 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Sticky bit on all world-writable directories");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"Policy", value:"CIS Ubuntu Linux 20.04 v2.0.0: 1.1.1.12 Ensure sticky bit is set on all world-writable directories (Automated)");
  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 1.1.21 Ensure sticky bit is set on all world-writable directories (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 1.1.21 Ensure sticky bit is set on all world-writable directories (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 5.1 Establish Secure Configurations");

  script_tag(name:"summary", value:"Setting the sticky bit on world writable directories prevents
users from deleting or renaming files in that directory that are not owned by them.

This feature prevents the ability to delete or rename files in world writable directories
(such as /tmp ) that are owned by another user.");

  exit(0);
}

include( "ssh_func.inc" );
include( "policy_functions.inc" );

cmd = "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null";
title = "Global writable directories without sticky bit.";
solution = "Run 'chmod a+t DIRECTORY' to set the sticky bit";
test_type = "SSH_Cmd";
default = "None";
value = "None";

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection";
}else{
  files = ssh_cmd( cmd:cmd, socket:sock, nosh:TRUE, return_errors:FALSE );
  if( files ) {
    compliant = "no";
    files_list = split( files, keep:FALSE );
    value = policy_build_string_from_list( list:files_list, sep:"," );
  }else{
    compliant = "yes";
  }
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );
policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );
