# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150438");
  script_version("2020-12-21T11:21:37+0000");
  script_tag(name:"last_modification", value:"2020-12-21 11:21:37 +0000 (Mon, 21 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-11-20 10:52:10 +0000 (Fri, 20 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("GaussDB Kernel: Configuring Kerberos Authentication in a Cluster");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gb_huawei_gaussdb_kernel_ssh_login_detect.nasl");
  script_mandatory_keys("huawei/gaussdb_kernel/detected", "Compliance/Launch");

  script_tag(name:"summary", value:"Use gs_om to enable and disable Kerberos authentication in a cluster.");

  exit(0);
}

include( "policy_functions.inc" );

cmd = "After the command is executed, a success message is displayed.
In addition, you can view the pg_hba.conf configuration file in the CN or DN data
directory to check whether the authentication mode of nodes in the cluster is gss,
that is, whether Kerberos authentication is enabled.
Run the cm_ctl query -Cv command to check the process status in the cluster. The
Kerberos process status is displayed.";
title = "Configuring Kerberos Authentication in a Cluster";
solution = "Ensure that the cluster is running properly.
gs_om -t stop
Run the following command. USER is the cluster initial user for installing the
server, IP1 indicates the IP address of the node where the primary server is
located, and IP2 indicates the IP address of the node where the standby server is
located. Specify any IP address in the cluster as the primary and secondary IP
addresses of the server.
gs_om -t kerberos -m install -U USER --krb-server IP1 --krb-standby IP2
gs_om -t kerberos -m install -U USER --krb-client
Run the following command on any node in the cluster to install the client:
gs_om -t kerberos -m install -U USER --krb-client
Restart the cluster.
gs_om -t start";
default = "If nodes in the database cluster have spoofing risks, enable
internal Kerberos authentication in the cluster.";
test_type = "Manual Check";

compliant = "incomplete";
value = "None";
comment = "Please check the value manually.";

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );
