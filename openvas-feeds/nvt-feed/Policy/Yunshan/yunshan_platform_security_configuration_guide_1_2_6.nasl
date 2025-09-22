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
  script_oid("1.3.6.1.4.1.25623.1.0.150679");
  script_version("2021-10-22T11:14:32+0000");
  script_tag(name:"last_modification", value:"2021-10-22 11:14:32 +0000 (Fri, 22 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-06-17 11:41:38 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Disabling Insecure Algorithms on the SSH Server/Client");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("Compliance/Launch", "huawei/vrp/yunshan/detected");

  script_tag(name:"summary", value:"Checks the algorithm configuration.");

  exit(0);
}

include( "policy_functions.inc" );
include( "ssh_func.inc" );

cmd = "display current-configuration configuration ssh";
title = "Disabling Insecure Algorithms on the SSH Server/Client";
solution = "Delete insecure algorithms from the configuration.";
test_type = "SSH_Cmd";
default = "Security risks exist if:
SSH server cipher configurations include 3des_cbc, aes128_cbc, aes192_cbc, aes256_cbc, arcfour128, arcfour256, blowfish_cbc, and des_cbc.
SSH client cipher configurations include 3des_cbc, aes128_cbc, aes192_cbc, aes256_cbc, arcfour128, arcfour256, blowfish_cbc, and des_cbc.
The HMAC configuration of the SSH server includes md5, md5_96, sha1, sha1_96, and sha2_256_96.
The SSH client HMAC configuration includes md5, md5_96, sha1, sha1_96, and sha2_256_96.
The ssh server key-exchange configuration includes dh_group1_sha1, dh_group_exchange_sha1, and dh_group14_sha1.
The SSH client key-exchange configurations include dh_group1_sha1, dh_group_exchange_sha1, and dh_group14_sha1.";

if( ! get_kb_item( "login/SSH/success" ) || ! sock = ssh_login_or_reuse_connection() ) {
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
} else {
  if( ! value = ssh_cmd( socket:sock, cmd:cmd, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
                         retry:10, force_reconnect:TRUE, clear_buffer:TRUE ) ) {
    compliant = "incomplete";
    value = "error";
    comment = "Command '" + cmd + "' did not return anything";
  } else if( value =~ "---- More ----" ) {
    # return was truncated
    compliant = "incomplete";
    value = "error";
    comment = "The return was truncated. Please set screen-length for this user-interface vty to 0.";
  } else {
    server_cipher = egrep( string:value, pattern:"ssh server cipher" );
    client_cipher = egrep( string:value, pattern:"ssh client cipher" );
    server_hmac = egrep( string:value, pattern:"ssh server hmac" );
    client_hmac = egrep( string:value, pattern:"ssh client hmac" );
    server_kex = egrep( string:value, pattern:"ssh server key-exchange" );
    client_kex = egrep( string:value, pattern:"ssh client key-exchange" );

    if( server_cipher && server_cipher =~ "(3des_cbc|aes128_cbc|aes192_cbc|aes256_cbc|arcfour128|arcfour256|blowfish_cbc|des_cbc)" ) {
      compliant = "no";
    }

    if( client_cipher && client_cipher =~ "(3des_cbc|aes128_cbc|aes192_cbc|aes256_cbc|arcfour128|arcfour256|blowfish_cbc|des_cbc)" ) {
      compliant = "no";
    }

    if( server_hmac && server_hmac =~ "(md5|md5_96|sha1|sha1_96|sha2_256_96)" ) {
      compliant = "no";
    }

    if( client_hmac && client_hmac =~ "(md5|md5_96|sha1|sha1_96|sha2_256_96)" ) {
      compliant = "no";
    }

    if( server_kex && server_kex =~ "(dh_group1_sha1|dh_group_exchange_sha1|dh_group14_sha1)" ) {
      compliant = "no";
    }

    if( client_kex && client_kex =~ "(dh_group1_sha1|dh_group_exchange_sha1|dh_group14_sha1)" ) {
      compliant = "no";
    }

    if( ! compliant ){
      compliant = "yes";
    }
  }
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );