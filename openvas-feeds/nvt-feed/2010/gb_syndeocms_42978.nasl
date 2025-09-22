# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:syndeocms:syndeocms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100784");
  script_version("2022-09-28T10:12:17+0000");
  script_tag(name:"last_modification", value:"2022-09-28 10:12:17 +0000 (Wed, 28 Sep 2022)");
  script_tag(name:"creation_date", value:"2010-09-06 14:44:23 +0200 (Mon, 06 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("SyndeoCMS <= 2.8.02 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_syndeocms_http_detect.nasl");
  script_mandatory_keys("syndeocms/detected");

  script_tag(name:"summary", value:"SyndeoCMS is prone to a local file include (LFI), a cross-site
  scripting (XSS) and an HTML-injection vulnerability because the application fails to properly
  sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting the local file-include issue allows remote attackers
  to view or execute local files within the context of the webserver process.

  An attacker may leverage the cross-site scripting and HTML-injection issues to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site. This may
  allow the attacker to steal cookie-based authentication credentials, render how the site is
  displayed, or to launch other attacks.");

  script_tag(name:"affected", value:"SyndeoCMS version 2.8.02 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42978");

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

if (version_is_less_equal(version: version, test_version: "2.8.02")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
