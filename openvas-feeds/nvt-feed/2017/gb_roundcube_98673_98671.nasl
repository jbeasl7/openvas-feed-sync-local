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

CPE = "cpe:/a:roundcube:webmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108170");
  script_version("2023-02-02T10:09:00+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-02-02 10:09:00 +0000 (Thu, 02 Feb 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2017-05-30 15:00:00 +0200 (Tue, 30 May 2017)");
  script_cve_id("CVE-2015-5381", "CVE-2015-5382", "CVE-2015-5383");
  script_name("Roundcube Webmail < 1.0.6, 1.1.x < 1.1.2 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_roundcube_http_detect.nasl");
  script_mandatory_keys("roundcube/detected");

  script_tag(name:"summary", value:"Roundcube Webmail is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2015-5381: XSS vulnerability in _mbox argument

  - CVE-2015-5382: security improvement in contact photo handling

  - CVE-2015-5383: potential info disclosure from temp directory");

  script_tag(name:"impact", value:"An attacker may leverage these issues to:

  - execute arbitrary script code in the browser of an unsuspecting user in the context of the
  affected site. This may allow the attacker to steal cookie-based authentication credentials
  and to launch other attacks

  - gain access to sensitive information. Information obtained may lead to further attacks");

  script_tag(name:"affected", value:"Roundcube Webmail versions prior to 1.0.6 and 1.1.x
  versions prior to 1.1.2.");

  script_tag(name:"solution", value:"Update to version 1.0.6, 1.1.2 or later.");

  script_xref(name:"URL", value:"https://roundcube.net/news/2015/06/05/updates-1.1.2-and-1.0.6-released");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98671");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98673");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.1.0", test_version2: "1.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
