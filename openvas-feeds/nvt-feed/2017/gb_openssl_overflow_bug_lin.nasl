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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107269");
  script_version("2022-08-22T10:11:10+0000");
  script_cve_id("CVE-2017-3738");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-22 10:11:10 +0000 (Mon, 22 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-19 11:49:00 +0000 (Fri, 19 Aug 2022)");
  script_tag(name:"creation_date", value:"2017-12-08 12:22:37 +0100 (Fri, 08 Dec 2017)");
  script_name("OpenSSL Overflow Vulnerability (20171207, 20180327) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20171207.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102118");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20180327.txt");

  script_tag(name:"summary", value:"OpenSSL is prone to an overflow bug.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The overflow bug is in the AVX2 Montgomery multiplication
  procedure used in exponentiation with 1024-bit moduli.");

  script_tag(name:"impact", value:"Successfully exploiting this issue would allow an attacker to
  derive information about the private key.");

  script_tag(name:"affected", value:"OpenSSL 1.0.2 before 1.0.2n. OpenSSL 1.1.0 before 1.1.0h.

  NOTE: This issue only affects 64-bit installations.");

  script_tag(name:"solution", value:"Update to version 1.0.2n, 1.1.0h or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.0\.2" && version_is_less(version:vers, test_version:"1.0.2n")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.2n", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

else if(vers =~ "^1\.1\.0" && version_is_less(version:vers, test_version:"1.1.0h")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.1.0h", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);