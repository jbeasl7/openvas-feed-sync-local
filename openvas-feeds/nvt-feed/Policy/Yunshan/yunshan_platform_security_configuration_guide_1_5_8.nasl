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
  script_oid("1.3.6.1.4.1.25623.1.0.150694");
  script_version("2021-10-22T11:14:32+0000");
  script_tag(name:"last_modification", value:"2021-10-22 11:14:32 +0000 (Fri, 22 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-06-18 06:36:35 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Configuring SNMPv3 User Password Complexity Check");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("Compliance/Launch", "huawei/vrp/yunshan/detected");

  script_tag(name:"summary", value:"Configures the password complexity check for SNMPv3 users.");

  exit(0);
}

include( "policy_functions.inc" );
include( "ssh_func.inc" );

cmd1 = "display snmp-agent sys-info version";
cmd2 = "display current-configuration | include snmp-agent";
cmd = cmd1 + '\n' + cmd2;
title = "Configuring SNMPv3 User Password Complexity Check";
solution = "Run the undo snmp-agent usm-user password complexity-check disable command to configure the password complexity check.";
test_type = "SSH_Cmd";
default = "If SNMPv3 is enabled, snmp-agent usm-user password complexity-check is enabled.";

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
} else {
  if( ! value = ssh_cmd( socket:sock, cmd:cmd1, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
                         retry:10, force_reconnect:TRUE, clear_buffer:TRUE ) ) {
    compliant = "incomplete";
    value = "error";
    comment = "Command '" + cmd1 + "' did not return anything";
  } else if( value =~ "---- More ----" ) {
    # return was truncated
    compliant = "incomplete";
    value = "error";
    comment = "The return was truncated. Please set screen-length for this user-interface vty to 0.";
  } else if( value =~ "SNMPv3" ) {
    value = cmd1 + ':\n' + value;
    if( ! value2 = ssh_cmd( socket:sock, cmd:cmd2, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
                            retry:10, force_reconnect:TRUE, clear_buffer:TRUE ) ) {
      compliant = "incomplete";
      value2 = "error";
      comment = "Command '" + cmd2 + "' did not return anything";
      value += '\n\n' + cmd2 + ':\n' + value2;
    } else if( value2 =~ "---- More ----" ) {
      # return was truncated
      compliant = "incomplete";
      value2 = "error";
      comment = "The return was truncated. Please set screen-length for this user-interface vty to 0.";
      value += '\n\n' + cmd2 + ':\n' + value2;
    } else if( value2 =~ "snmp-agent\s+usm-user\s+password\s+complexity-check\s+disable" &&
               value2 !~ "undo\s+snmp-agent\s+usm-user\s+password\s+complexity-check\s+disable" ) {
      compliant = "no";
      value += '\n\n' + cmd2 + ':\n' + value2;
    } else {
      compliant = "yes";
      value += '\n\n' + cmd2 + ':\n' + value2;
    }
  } else {
    value = cmd1 + ':\n' + value;
    compliant = "yes";
    comment = "SNMPv3 disabled.";
  }
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );