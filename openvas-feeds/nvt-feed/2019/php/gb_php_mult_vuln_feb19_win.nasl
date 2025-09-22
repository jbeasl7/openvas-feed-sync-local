# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142049");
  script_version("2021-11-26T13:39:39+0000");
  script_tag(name:"last_modification", value:"2021-11-26 13:39:39 +0000 (Fri, 26 Nov 2021)");
  script_tag(name:"creation_date", value:"2019-02-26 10:40:54 +0700 (Tue, 26 Feb 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-18 18:15:00 +0000 (Tue, 18 Jun 2019)");

  script_cve_id("CVE-2016-10166", "CVE-2019-9020", "CVE-2019-9021", "CVE-2019-9023", "CVE-2019-9024",
                "CVE-2019-6977");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Multiple Vulnerabilities (Feb 2019) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Fixed bug #77269 (efree() on uninitialized Heap data in imagescale leads to use-after-free).
  (CVE-2016-10166)

  - Fixed bug #77270 (imagecolormatch Out Of Bounds Write on Heap). (CVE-2019-6977)

  - Fixed bug #77370 (Buffer overflow on mb regex functions - fetch_token). (CVE-2019-9023)

  - Fixed bug #77371 (heap buffer overflow in mb regex functions - compile_string_node).
  (CVE-2019-9023)

  - Fixed bug #77381 (heap buffer overflow in multibyte match_at). (CVE-2019-9023)

  - Fixed bug #77382 (heap buffer overflow due to incorrect length in expand_case_fold_string).
  (CVE-2019-9023)

  - Fixed bug #77385 (buffer overflow in fetch_token). (CVE-2019-9023)

  - Fixed bug #77394 (Buffer overflow in multibyte case folding - unicode). (CVE-2019-9023)

  - Fixed bug #77418 (Heap overflow in utf32be_mbc_to_code). (CVE-2019-9023)

  - Fixed bug #77247 (heap buffer overflow in phar_detect_phar_fname_ext). (CVE-2019-9021)

  - Fixed bug #77242 (heap out of bounds read in xmlrpc_decode()). (CVE-2019-9020)

  - Fixed bug #77380 (Global out of bounds read in xmlrpc base64 code). (CVE-2019-9024)");

  script_tag(name:"affected", value:"PHP versions before 5.6.40, 7.x before 7.1.26, 7.2.x before
  7.2.14 and 7.3.x before 7.3.1.");

  script_tag(name:"solution", value:"Update to version 5.6.40, 7.1.16, 7.2.14, 7.3.1 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77269");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77270");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77370");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77371");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77381");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77382");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77385");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77394");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77418");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77247");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77242");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77380");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "5.6.40")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.40", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.1.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.26", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.2", test_version2: "7.2.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.14", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "7.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);