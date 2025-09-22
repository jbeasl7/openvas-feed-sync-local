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
  script_oid("1.3.6.1.4.1.25623.1.0.150675");
  script_version("2021-10-22T11:14:32+0000");
  script_tag(name:"last_modification", value:"2021-10-22 11:14:32 +0000 (Fri, 22 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-06-17 11:41:38 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: The length of the peer public key does not meet security requirements");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("Compliance/Launch", "huawei/vrp/yunshan/detected");

  script_tag(name:"summary", value:"Check whether the peer public key of the RSA, DSA and ECC is too short.");

  exit(0);
}

include( "policy_functions.inc" );
include( "ssh_func.inc" );

cmd1 = "disp rsa peer-public-key brief";
cmd2 = "disp dsa peer-public-key brief";
cmd3 = "disp ecc peer-public-key brief";
cmd = cmd1 + '\n' + cmd2 + '\n' + cmd3;
title = "The length of the peer public key does not meet security requirements";
solution = "1. The length of the RSA and DSA keys on the server must be greater than or equal to 2048.
2. The ecdsa length on the server must be greater than or equal to 256 characters.";
test_type = "SSH_Cmd";
default = "RSA and DSA keys >= 2048. ecdsa length >= 256 characters.";

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
} else {
  if( ! value1 = ssh_cmd( socket:sock, cmd:cmd1, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
                          retry:10, force_reconnect:TRUE, clear_buffer:TRUE ) ) {
    compliant = "incomplete";
    value = "error";
    comment = "Command '" + cmd1 + "' did not return anything";
  } else if( ! value2 = ssh_cmd( socket:sock, cmd:cmd2, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
                                 retry:10, force_reconnect:TRUE, clear_buffer:TRUE ) ) {
    compliant = "incomplete";
    value = "error";
    comment = "Command '" + cmd2 + "' did not return anything";
  } else if( ! value3 = ssh_cmd( socket:sock, cmd:cmd3, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
                                 retry:10, force_reconnect:TRUE, clear_buffer:TRUE ) ) {
    compliant = "incomplete";
    value = "error";
    comment = "Command '" + cmd3 + "' did not return anything";
  } else if( value1 =~ "---- More ----" || value2 =~ "---- More ----" || value3 =~ "---- More ----" ) {
    # return was truncated
    compliant = "incomplete";
    value = "error";
    comment = "The return was truncated. Please set screen-length for this user-interface vty to 0.";
  } else if( value1 !~ "Info: Peer key is not present" ) {
    # 2021-06-17 21:32:28.807
    # ---------------------------------------------------------------------------
    #       Bits Name
    # ---------------------------------------------------------------------------
    #       2048 rsa01
    # ---------------------------------------------------------------------------
    # <HUAWEI>
    foreach line( split( value1, keep:FALSE ) ) {
      if( line =~ "-------------" )
        continue;

      if( line =~ "\s+Bits\s+Name\s*" )
        continue;

      bits = eregmatch( string:line, pattern:"^\s*([0-9]+)\s+.*$" );
      if( bits && int(bits[1]) < 2048 )
        compliant = "no";
    }

    if( value2 !~ "Info: Peer key is not present" ) {
      # 2021-06-17 21:32:28.807
      # ---------------------------------------------------------------------------
      #       Bits Name
      # ---------------------------------------------------------------------------
      #       2048 test
      # ---------------------------------------------------------------------------
      # <HUAWEI>
      foreach line( split( value2, keep:FALSE ) ) {
        if( line =~ "-------------" )
          continue;

        if( line =~ "\s+Bits\s+Name\s*" )
          continue;

        bits = eregmatch( string:line, pattern:"^\s*([0-9]+)\s+.*$" );
        if( bits && int(bits[1]) < 2048 )
          compliant = "no";
      }
    }

    if( value3 !~ "Info: Peer key is not present" ) {
      # 2021-06-17 21:32:28.807
      # ---------------------------------------------------------------------------
      #       Bits Name
      # ---------------------------------------------------------------------------
      #       521 127.0.0.1
      # ---------------------------------------------------------------------------
      # <HUAWEI>
      foreach line( split( value3, keep:FALSE ) ) {
        if( line =~ "-------------" )
          continue;

        if( line =~ "\s+Bits\s+Name\s*" )
          continue;

        bits = eregmatch( string:line, pattern:"^\s*([0-9]+)\s+.*$" );
        if( bits && int(bits[1]) < 256 )
          compliant = "no";
      }
    }

    if( ! compliant )
      compliant = "yes";

    value = cmd1 + ':\n' + value1;
    value += '\n\n' + cmd2 + ':\n' + value2;
    value += '\n\n' + cmd3 + ':\n' + value3;
  }
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );