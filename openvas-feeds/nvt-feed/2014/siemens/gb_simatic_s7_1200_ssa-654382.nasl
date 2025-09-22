# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:siemens:simatic_s7_1200";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103930");
  script_cve_id("CVE-2014-2254", "CVE-2014-2256", "CVE-2014-2258");
  script_version("2022-04-27T04:20:28+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Siemens SIMATIC S7-1200 Multiple DoS Vulnerabilities (SSA-654382)");

  script_xref(name:"URL", value:"https://cert-portal.siemens.com/productcert/pdf/ssa-654382.pdf");
  script_xref(name:"URL", value:"http://ics-cert.us-cert.gov/advisories/ICSA-14-079-02");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66349");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66353");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66344");

  script_tag(name:"last_modification", value:"2022-04-27 04:20:28 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-03-31 13:32:29 +0200 (Mon, 31 Mar 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_siemens_simatic_s7_consolidation.nasl");
  script_mandatory_keys("siemens/simatic_s7/detected");

  script_tag(name:"summary", value:"Siemens SIMATIC S7-1200 devices are prone to multiple denial of
  service (DoS) vulnerabilities.");

  script_tag(name:"impact", value:"Remote attackers may exploit this issue to cause DoS conditions,
  denying service to legitimate users.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Siemens SIMATIC S7-1200 CPU PLC devices with firmware before 4.0
  allow remote attackers to cause a denial of service (defect-mode transition) via crafted HTTP
  packets, crafted ISO-TSAP packets or crafted HTTPS packets.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"affected", value:"Versions prior to 4.0 are vulnerable.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if(version =~ "^[23]\.") {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
