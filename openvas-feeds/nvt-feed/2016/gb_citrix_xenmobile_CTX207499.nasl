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

CPE = "cpe:/a:citrix:xenmobile_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105580");
  script_version("2022-09-16T10:11:41+0000");
  script_tag(name:"last_modification", value:"2022-09-16 10:11:41 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"creation_date", value:"2016-03-18 11:15:00 +0100 (Fri, 18 Mar 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:25:00 +0000 (Sat, 03 Dec 2016)");

  script_cve_id("CVE-2016-2789");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix XenMobile XSS Vulnerability (CTX207499)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_citrix_xenmobile_http_detect.nasl");
  script_mandatory_keys("citrix/endpoint_management/detected");

  script_tag(name:"summary", value:"Citrix XenMobile is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This vulnerability could potentially be used to execute
  malicious client-side script in the same context as legitimate content from the web server, if
  this vulnerability is used to execute script in the browser of an authenticated administrator
  then the script may be able to gain access to the administrator's session or other potentially
  sensitive information.");

  script_tag(name:"affected", value:"All versions of Citrix XenMobile Server 10.0

  Citrix XenMobile Server 10.1 earlier than Rolling Patch 4

  Citrix XenMobile Server 10.3 earlier than Rolling Patch 1");

  script_tag(name:"solution", value:"Update to version 10.3 Rolling Patch 1, 10.1 Rolling Patch 4
  or later.");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX207499");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

patch = get_kb_item("citrix_xenmobile_server/patch_release");

if (version =~ "^10\.0")
  fix = "10.1 Rolling Patch 4";

if (version =~ "^10\.1") {
  if (patch) {
    if (patch == "no_patches")
      fix = "10.1 Rolling Patch 4";
    else if (version_is_less(version: patch, test_version: "10.1.0.68170"))
      fix = "10.1 Rolling Patch 4";
  } else {
    if (version_is_less_equal(version: version, test_version: "10.1.0.0"))
      fix = "10.1 Rolling Patch 4";
  }
}

if (version =~ "^10\.3") {
  if (patch) {
    if(patch == "no_patches")
      fix = "10.3 Rolling Patch 1";
    else if (version_is_less(version: patch, test_version: "10.3.0.10004"))
      fix = "10.3 Rolling Patch 1";
  } else {
    if (version_is_less_equal(version: version, test_version: "10.3.0.0"))
      fix = "10.3 Rolling Patch 1";
  }
}

if (fix) {
    report = report_fixed_ver(installed_version: version, fixed_version: version,
                              installed_patch: patch, fixed_patch: fix);
    security_message(port: port, data: report);
    exit(0);
}

exit(99);
