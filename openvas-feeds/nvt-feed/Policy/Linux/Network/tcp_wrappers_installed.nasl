# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.150542");
  script_version("2021-03-03T15:26:07+0000");
  script_tag(name:"last_modification", value:"2021-03-03 15:26:07 +0000 (Wed, 03 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-01-11 12:50:39 +0000 (Mon, 11 Jan 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Install TCP Wrappers");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 3.3.1 Ensure TCP Wrappers is installed (Not Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 9.4 Apply Host-based Firewalls or Port Filtering");

  script_tag(name:"summary", value:"Many Linux distributions provide value-added firewall solutions which provide easy,
advanced management of network traffic into and out of the local system. When these
solutions are available and appropriate for an environment they should be used.
In cases where a value-added firewall is not provided by a distribution, TCP Wrappers
provides a simple access list and standardized logging method for services capable of
supporting it. Services that are called from inetd and xinetd support the use of TCP
wrappers. Any service that can support TCP wrappers will have the libwrap.so library
attached to it.");

  exit(0);
}

include("policy_functions.inc");

cmd = "[rpm -q, dpkg -s] tcp_wrappers tcpd";
title = "Install TCP Wrappers";
solution = "Install package 'tcp_wrappers' or 'tcpd'";
test_type = "SSH_Cmd";
default = "Installed";

if(!get_kb_item("login/SSH/success")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else{
  tcp_wrappers_installed = get_package_version(package:"tcp_wrappers");
  tcpd_installed = get_package_version(package:"tcpd");

  if(tcp_wrappers_installed || tcpd_installed)
    value = "Installed";
  else
    value = "Not installed";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
