# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150684");
  script_version("2021-10-22T11:14:32+0000");
  script_tag(name:"last_modification", value:"2021-10-22 11:14:32 +0000 (Fri, 22 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-06-17 11:41:38 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: No password rule is configured");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("Compliance/Launch", "huawei/vrp/yunshan/detected");

  script_tag(name:"summary", value:"If the password check policy is disabled, you can configure
  simple passwords to increase the risk of brute force cracking.");

  exit(0);
}

include( "policy_functions.inc" );
include( "ssh_func.inc" );

cmd1 = "display current-configuration | ignore-case include user-security-policy";
cmd2 = "display current-configuration | ignore-case include user-password complexity-check";
cmd3 = "display current-configuration | ignore-case include user-password min-len";
cmd = cmd1 + '\n' + cmd2 + '\n' + cmd3;
title = "No password rule is configured";
solution = "If the undo user-security-policy enable command exists, delete the command.
This command is added in the AAA view when the user-password complexity-check does not exist.
If the value of user-password min-len is less than 6, set this parameter to a value greater than or equal to 6.";
test_type = "SSH_Cmd";
default = "'undo user-security-policy enable' does not exists.
user-password min-len greater or equal to 6.";

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
} else {
  if( ! value1 = ssh_cmd( socket:sock, cmd:cmd1, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
                          retry:10, force_reconnect:TRUE, clear_buffer:TRUE ) ) {
    compliant = "incomplete";
    value = "error";
    comment = "Command '" + cmd + "' did not return anything";
  } else if( ! value2 = ssh_cmd( socket:sock, cmd:cmd2, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
                                 retry:10, force_reconnect:TRUE, clear_buffer:TRUE ) ) {
    compliant = "incomplete";
    value = "error";
    comment = "Command '" + cmd + "' did not return anything";
  } else if( ! value3 = ssh_cmd( socket:sock, cmd:cmd3, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
                                 retry:10, force_reconnect:TRUE, clear_buffer:TRUE ) ) {
    compliant = "incomplete";
    value = "error";
    comment = "Command '" + cmd + "' did not return anything";
  } else if( value1 =~ "---- More ----" || value2 =~ "---- More ----" || value3 =~ "---- More ----" ) {
    # return was truncated
    compliant = "incomplete";
    value = "error";
    comment = "The return was truncated. Please set screen-length for this user-interface vty to 0.";
  } else {
    value = cmd1 + ':\n' + value1;
    value += '\n\n' + cmd2 + ':\n' + value2;
    value += '\n\n' + cmd3 + ':\n' + value3;

    if( value1 =~ "undo\s+user-security-policy\s+enable" )
      compliant = "no";

    if( value2 !~ "user-password\s+complexity-check" )
      compliant = "no";

    if( value3 !~ "user-password\s+min-len" )
      compliant = "no";
    else {
      min_len = eregmatch( string:value3, pattern:"user-password\s+min-len\s+([0-9]+)" );
      if( min_len ) {
        if( int( min_len[1] ) < 6 )
          compliant = "no";
      }
    }

    if( ! compliant )
      compliant = "yes";
  }
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );