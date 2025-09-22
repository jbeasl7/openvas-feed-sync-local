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

CPE = "cpe:/a:tor:tor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804934");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-5117");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-10-14 10:45:19 +0530 (Tue, 14 Oct 2014)");

  script_name("Tor 'Relay Early' Traffic Confirmation Attack Vulnerability (Oct 2014) - Linux");

  script_tag(name:"summary", value:"Tor is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the handling of sequences of
  Relay and Relay Early commands.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to manipulate
  protocol headers and perform traffic confirmation attack.");

  script_tag(name:"affected", value:"Tor before 0.2.4.23 and 0.2.5 before 0.2.5.6-alpha.");

  script_tag(name:"solution", value:"Update to version 0.2.4.23, 0.2.5.6-alpha or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/95053");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68968");
  script_xref(name:"URL", value:"https://blog.torproject.org/blog/tor-security-advisory-relay-early-traffic-confirmation-attack");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_tor_detect_lin.nasl");
  script_mandatory_keys("Tor/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"0.2.4.23") ||
   version_in_range(version:vers, test_version:"0.2.5", test_version2:"0.2.5.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.2.4.23/0.2.5.6-alpha");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);