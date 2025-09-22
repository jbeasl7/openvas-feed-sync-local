# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:zimbra:collaboration";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113085");
  script_version("2022-08-18T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-08-18 10:11:39 +0000 (Thu, 18 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-01-17 15:45:55 +0100 (Wed, 17 Jan 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 20:01:00 +0000 (Tue, 09 Oct 2018)");

  script_cve_id("CVE-2017-8802");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zimbra < 8.8.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zimbra_consolidation.nasl");
  script_mandatory_keys("zimbra/detected");

  script_tag(name:"summary", value:"Zimbra is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote attackers can target the vulnerability by sending an
  Email with XSS payload (e.g. JavaScript) in its body. In case the recipient selects the email in
  the Zimbra client, and accesses the 'Show Snippet' functionality using the 'Q' shortcut, the XSS
  payload is executed in the context of the recipient's Zimbra client.");

  script_tag(name:"impact", value:"Beside others, the malicious payload could compromise the
  confidentility, integrity as well as availability of the victim's emails. Also it could be
  possible to change Zimbra settings of the corresponding victim.");

  script_tag(name:"affected", value:"Zimbra prior to version 8.8.0.");

  script_tag(name:"solution", value:"Update to version 8.8.0 or later.");

  script_xref(name:"URL", value:"https://www.compass-security.com/fileadmin/Datein/Research/Advisories/CSNC-2018-001_zimbra_stored_xss.txt");
  script_xref(name:"URL", value:"https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "8.8.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.8.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
