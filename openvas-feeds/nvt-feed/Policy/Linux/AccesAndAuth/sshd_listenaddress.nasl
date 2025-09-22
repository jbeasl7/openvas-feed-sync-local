# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150095");
  script_version("2021-12-01T13:53:02+0000");
  script_tag(name:"last_modification", value:"2021-12-01 13:53:02 +0000 (Wed, 01 Dec 2021)");
  script_tag(name:"creation_date", value:"2020-01-20 14:28:39 +0100 (Mon, 20 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: SSH ListenAddress");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sshd_config");

  script_tag(name:"summary", value:"ListenAddress specifies the local address sshd should listen on.
If port is not specified, sshd will listen on the address and all prior Port options specified. The
default is to listen on all local addresses. Multiple ListenAddress options are permitted.
Additionally, any Port options must precede this option for non-port qualified addresses.

Note: This test will fail if the default is used or if configured to listen on all local addresses.");

  exit(0);
}

include( "ssh_func.inc" );
include( "policy_functions.inc" );
include("host_details.inc");

cmd = "grep '^ListenAddress' /etc/ssh/sshd_config";
title = "SSH ListenAddress";
solution = "Edit /etc/ssh/sshd_config";
test_type = "SSH_Cmd";
default = "IPv4 / IPv6";

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else{
  listenaddress = ssh_cmd(socket:sock, cmd:cmd, nosh:TRUE, return_errors:TRUE);
  value = listenaddress;

  if(!listenaddress){
    value = "Default (none specified)";
    compliant = "no";
  }else{
    foreach address(split(listenaddress, keep:FALSE)){
      if(address =~ "^\s*ListenAddress\s+(0\.0\.0\.0|::)$"){
        compliant = "no";
        comment = "Set 'ListenAddress' to an address other than '0.0.0.0' or '::'. If not configured,
        set one or more addresses accordingly.";
      }
    }
  }
  if(compliant !~ "no"){
    compliant = "yes";
  }
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit(0);
