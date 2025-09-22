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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808197");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-3092");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-17 08:15:00 +0000 (Sat, 17 Jul 2021)");
  script_tag(name:"creation_date", value:"2016-07-13 19:19:54 +0530 (Wed, 13 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Tomcat 'MultipartStream' Class DoS Vulnerability - Windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in the
  'MultipartStream' class in Apache Commons Fileupload when processing
  multi-part requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (CPU consumption).");

  script_tag(name:"affected", value:"Apache Tomcat 7.x before 7.0.70, 8.0.0.RC1 before 8.0.36,
  8.5.x before 8.5.3, and 9.0.0.M1 before 9.0.0.M7.");

  script_tag(name:"solution", value:"Upgrade to version 7.0.70, or 8.0.36,
  or 8.5.3, or 9.0.0.M7, or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91453");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( appPort = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:appPort, exit_no_version:TRUE ) )
  exit( 0 );

appVer = infos["version"];
path = infos["location"];

if(appVer =~ "^[7-9]\.")
{
  if(version_in_range(version:appVer, test_version:"7.0.1", test_version2:"7.0.69"))
  {
    fix = "7.0.70";
    VULN = TRUE;
  }

  else if(version_in_range(version:appVer, test_version:"8.5.0", test_version2:"8.5.2"))
  {
    fix = "8.5.3";
    VULN = TRUE;
  }

  else if(version_in_range(version:appVer, test_version:"8.0.0.RC1", test_version2:"8.0.35"))
  {
    fix = "8.0.36";
    VULN = TRUE;
  }

  else if(version_in_range(version:appVer, test_version:"9.0.0.M1", test_version2:"9.0.0.M7"))
  {
    fix = "9.0.0.M8";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:appVer, fixed_version:fix, install_path:path);
    security_message(data:report, port:appPort);
    exit(0);
  }
}
