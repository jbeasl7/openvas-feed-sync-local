# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801841");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)");
  script_cve_id("CVE-2010-4641", "CVE-2010-4642");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("XWiki Enterprise Unspecified SQL Injection and XSS Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42058");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44601");
  script_xref(name:"URL", value:"http://www.xwiki.org/xwiki/bin/view/ReleaseNotes/ReleaseNotesXWikiEnterprise25");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary script
  code or cause SQL Injection attack and gain sensitive information.");

  script_tag(name:"affected", value:"XWiki Enterprise before 2.5.");

  script_tag(name:"insight", value:"The flaws are caused by input validation errors when processing user-supplied
  data and parameters, which could allow remote attackers to execute arbitrary
  script code or manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"Upgrade to XWiki Enterprise 2.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"XWiki Enterprise is prone to unspecified SQL injection and cross site scripting vulnerabilities.");

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

if (version_is_less(version: version, test_version: "2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
