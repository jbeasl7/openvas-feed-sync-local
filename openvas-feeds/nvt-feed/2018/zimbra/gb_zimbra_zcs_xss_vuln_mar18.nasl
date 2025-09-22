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
  script_oid("1.3.6.1.4.1.25623.1.0.112249");
  script_version("2025-01-28T05:37:13+0000");
  script_tag(name:"last_modification", value:"2025-01-28 05:37:13 +0000 (Tue, 28 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-03-29 13:30:55 +0100 (Thu, 29 Mar 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-27 18:28:13 +0000 (Mon, 27 Jan 2025)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  script_cve_id("CVE-2018-6882");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Patch not detected

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zimbra < 8.7.11 Patch 1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zimbra_consolidation.nasl");
  script_mandatory_keys("zimbra/detected");

  script_tag(name:"summary", value:"Zimbra is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A cross-site scripting (XSS) vulnerability in the
  ZmMailMsgView.getAttachmentLinkHtml function might allow remote attackers to inject arbitrary web
  script or HTML via a Content-Location header in an email attachment.");

  script_tag(name:"affected", value:"Zimbra prior to version 8.7.11 Patch 1 and version 8.8.x prior
  to 8.8.7.");

  script_tag(name:"solution", value:"Update to version 8.7.11 Patch 1, 8.8.7 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Mar/52");
  script_xref(name:"URL", value:"https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "8.7.11")) {
  vuln = TRUE;
  fix = "8.7.11 Patch 1";
}

if (version_in_range(version: version, test_version: "8.8.0", test_version2: "8.8.6")) {
  vuln = TRUE;
  fix = "8.8.7";
}

if (vuln) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
