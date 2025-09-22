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
  script_oid("1.3.6.1.4.1.25623.1.0.812894");
  script_version("2025-08-18T05:42:33+0000");
  script_tag(name:"last_modification", value:"2025-08-18 05:42:33 +0000 (Mon, 18 Aug 2025)");
  script_tag(name:"creation_date", value:"2018-05-31 11:07:20 +0530 (Thu, 31 May 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-15 20:22:40 +0000 (Fri, 15 Aug 2025)");

  script_cve_id("CVE-2018-10951", "CVE-2018-10949", "CVE-2018-10950");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Patch not detected

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zimbra 8.6.x < 8.6.0 Patch10, 8.7.x < 8.7.11 Patch3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zimbra_consolidation.nasl");
  script_mandatory_keys("zimbra/detected");

  script_tag(name:"summary", value:"Zimbra is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - GetServer, GetAllServers, or GetAllActiveServers call in the Admin SOAP API.

  - Discrepancy between the 'HTTP 404 - account is not active' and 'HTTP 401 - must authenticate'
  errors.

  - Verbose error messages containing a stack dump, tracing data, or full user-context dump.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to read
  zimbraSSLPrivateKey, do account enumeration and expose information.");

  script_tag(name:"affected", value:"Zimbra 8.6x through 8.6.0 Patch9 and 8.7.x through 8.7.11
  Patch2.");

  script_tag(name:"solution", value:"Update to version 8.6.0 Patch10, 8.7.11 Patch3 or later.");

  script_xref(name:"URL", value:"https://bugzilla.zimbra.com/show_bug.cgi?id=108963");
  script_xref(name:"URL", value:"https://bugzilla.zimbra.com/show_bug.cgi?id=108962");
  script_xref(name:"URL", value:"https://bugzilla.zimbra.com/show_bug.cgi?id=108894");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_equal(version: version, test_version: "8.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version:"8.6.0", fixed_patch: "10");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.7.0", test_version2: "8.7.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version:"8.7.11", fixed_patch: "3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
