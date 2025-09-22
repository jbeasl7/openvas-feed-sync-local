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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813507");
  script_version("2022-08-18T10:11:39+0000");
  script_tag(name:"last_modification", value:"2022-08-18 10:11:39 +0000 (Thu, 18 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-06-05 14:03:30 +0530 (Tue, 05 Jun 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-04 12:32:00 +0000 (Thu, 04 Jun 2020)");

  script_cve_id("CVE-2018-10939");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zimbra 8.7.x < 8.7.11 Patch4, 8.8.x < 8.8.8 Patch4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zimbra_consolidation.nasl");
  script_mandatory_keys("zimbra/detected");

  script_tag(name:"summary", value:"Zimbra is prone to a persistent cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient input validation in contact
  groups.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute
  arbitrary script code in a user's browser session within the trust relationship.");

  script_tag(name:"affected", value:"Zimbra version 8.7.x through 8.7.11 Patch3 and 8.8.x through
  8.8.8 Patch3.");

  script_tag(name:"solution", value:"Update to version 8.7.11 Patch4, 8.8.8 Patch4 or later.");

  script_xref(name:"URL", value:"https://blog.zimbra.com/2018/05/new-zimbra-patches-8-8-8-patch-4-and-8-7-11-patch-4/");
  script_xref(name:"URL", value:"https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "8.7.0", test_version2: "8.7.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.7.11", fixed_patch: "4");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.8.0", test_version2: "8.8.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.8.8", fixed_patch: "4");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
