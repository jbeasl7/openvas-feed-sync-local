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
  script_oid("1.3.6.1.4.1.25623.1.0.150347");
  script_version("2020-12-21T11:24:45+0000");
  script_tag(name:"last_modification", value:"2020-12-21 11:24:45 +0000 (Mon, 21 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-11-11 15:21:37 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("openGauss: Prohibiting host Entries from Using MD5 Authentication in the pg_hba.conf File");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gb_huawei_opengauss_ssh_login_detect.nasl", "compliance_tests.nasl");
  script_mandatory_keys("huawei/opengauss/detected", "Compliance/Launch");

  script_xref(name:"URL", value:"https://opengauss.org");

  script_tag(name:"summary", value:"MD5 authentication is insecure. You are advised to use SHA256 authentication.");

  exit(0);
}

include( "policy_functions.inc" );

cmd = "grep -P '^[^#]*host(ssl|nossl)?\s+.+[Mm][Dd][5]\s*$' ${GAUSSDATA}/pg_hba.conf";
title = "Prohibiting host Entries from Using MD5 Authentication in the pg_hba.conf File";
solution = "Configure SHA256 authentication for the host entries in the pg_hba.conf file.";
default = "N/A";
test_type = "Manual Check";

compliant = "incomplete";
value = "None";
comment = "Please check the value manually.";

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );
