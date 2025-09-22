# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807920");
  script_version("2022-09-08T10:11:29+0000");
  script_cve_id("CVE-2016-2390");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-09-08 10:11:29 +0000 (Thu, 08 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:04:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-04-21 16:02:44 +0530 (Thu, 21 Apr 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Squid DoS Vulnerability (SQUID-2016:1) - Linux");

  script_tag(name:"summary", value:"Squid is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the 'FwdState::connectedToPeer' method of the
  'FwdState.cc' script which does not properly handle SSL handshake errors when built with
  the --with-openssl option.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service.");

  script_tag(name:"affected", value:"Squid version 3.5.13 and 4.0.4 before 4.0.6.");

  script_tag(name:"solution", value:"Update to version 3.5.14, 4.0.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://lists.squid-cache.org/pipermail/squid-announce/2016-February/000038.html");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2016_1.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_squid_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("squid/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^[34]\.") {
  if(version_is_equal(version:vers, test_version:"3.5.13")) {
    fix = "3.5.14";
    VULN = TRUE;
  }

  else if(version_in_range(version:vers, test_version:"4.0.4", test_version2:"4.0.5")) {
    fix = "4.0.6";
    VULN = TRUE;
  }

  if(VULN) {
    report = report_fixed_ver(installed_version:vers, fixed_version:fix);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
