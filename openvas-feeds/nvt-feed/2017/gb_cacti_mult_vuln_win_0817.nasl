# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:cacti:cacti";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108208");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-08-16 11:05:37 +0200 (Wed, 16 Aug 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-08 01:29:00 +0000 (Fri, 08 Sep 2017)");

  script_cve_id("CVE-2013-1434", "CVE-2013-1435", "CVE-2013-5588", "CVE-2013-5589", "CVE-2014-2327",
                "CVE-2014-2328", "CVE-2014-2708", "CVE-2014-2709", "CVE-2014-4002", "CVE-2014-5025",
                "CVE-2014-5026", "CVE-2014-5261", "CVE-2014-5262", "CVE-2017-1000031", "CVE-2017-1000032");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cacti <= 0.8.8b Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_cacti_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Cacti is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2013-1434, CVE-2013-5589, CVE-2014-2708, CVE-2014-5262, CVE-2017-1000031: Multiple SQL
  injection (SQLi)

  - CVE-2013-1435, CVE-2014-2328, CVE-2014-2709, CVE-2014-5261: Remote code execution (RCE)

  - CVE-2013-5588, CVE-2014-4002, CVE-2014-5025, CVE-2014-5026, CVE-2017-1000032: Multiple
  cross-site scripting (XSS)

  - CVE-2014-2327: Cross-site request forgery (CSRF)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Cacti version 0.8.8b and prior.");

  script_tag(name:"solution", value:"Update to version 0.8.8c or later.");

  script_xref(name:"URL", value:"http://bugs.cacti.net/view.php?id=2383");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61657");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62001");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66392");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66387");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66555");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66630");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68257");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68759");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69213");
  script_xref(name:"URL", value:"http://bugs.cacti.net/view.php?id=2405");
  script_xref(name:"URL", value:"http://bugs.cacti.net/view.php?id=2456");
  script_xref(name:"URL", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=742768");
  script_xref(name:"URL", value:"http://forums.cacti.net/viewtopic.php?f=21&t=50593");
  script_xref(name:"URL", value:"https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2016-007");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "0.8.8b")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.8.8c");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
