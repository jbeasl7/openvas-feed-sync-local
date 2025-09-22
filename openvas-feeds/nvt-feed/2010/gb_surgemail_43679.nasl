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

CPE = "cpe:/a:netwin:surgemail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100842");
  script_version("2022-05-24T09:30:09+0000");
  script_tag(name:"last_modification", value:"2022-05-24 09:30:09 +0000 (Tue, 24 May 2022)");
  script_tag(name:"creation_date", value:"2010-10-05 12:35:02 +0200 (Tue, 05 Oct 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-3201");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SurgeMail < 4.3g XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_surgemail_consolidation.nasl");
  script_mandatory_keys("surgemail/detected");

  script_tag(name:"summary", value:"SurgeMail is prone to a cross-site scripting (XSS) vulnerability
  because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This can allow
  the attacker to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"SurgeMail version 4.3e and prior.");

  script_tag(name:"solution", value:"Update to version 4.3g or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43679");
  script_xref(name:"URL", value:"http://ictsec.se/?p=108");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "4.3e")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3g");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
