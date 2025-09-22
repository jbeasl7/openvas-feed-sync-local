# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/o:cisco:nx-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103818");
  script_version("2022-12-26T10:12:01+0000");
  script_tag(name:"last_modification", value:"2022-12-26 10:12:01 +0000 (Mon, 26 Dec 2022)");
  script_tag(name:"creation_date", value:"2013-10-22 17:24:45 +0200 (Tue, 22 Oct 2013)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2013-1121");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco NX-OS Software BGP Regex Vulnerability (Cisco-SA-20130917-CVE-2013-1121)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_nx_os_consolidation.nasl");
  script_mandatory_keys("cisco/nx_os/detected", "cisco/nx_os/device", "cisco/nx_os/model");

  script_tag(name:"summary", value:"A vulnerability in the Border Gateway Protocol (BGP) code of
  Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause the affected device
  to reload.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to an issue with the regex engine used
  when processing complex regular expressions. An attacker could exploit this vulnerability by
  injecting specific autonomous system (AS) path sets. If the affected device has a complex regular
  expression applied to the inbound routes, the vulnerability may be triggered.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to trigger Cisco NX-OS
  Software to restart.");

  script_tag(name:"affected", value:"Cisco Nexus 7000 Series running on NX-OS.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62446");
  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/support/docs/csa/Cisco-SA-20130917-CVE-2013-1121.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!device = get_kb_item("cisco/nx_os/device"))
  exit(0);

if (device != "Nexus")
  exit(0);

if (!model = get_kb_item("cisco/nx_os/model"))
  exit(0);

if (model !~ "^C?7")
  exit(0);

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

vers = ereg_replace( pattern:'[()]', replace:".", string:version );
vers = ereg_replace( pattern:'\\.$', replace:"", string:vers );

ff    = make_list( "5.2.1.N1.3", "6.0.2.N2.1" );
fixed = "6.2.1.81.S0";

foreach first_found( ff ) {
  if( revcomp( a:vers, b:first_found ) >= 0 ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"6.2(1.81)S0" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
