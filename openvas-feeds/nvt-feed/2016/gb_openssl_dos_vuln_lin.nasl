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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806816");
  script_version("2021-05-10T10:17:46+0000");
  script_cve_id("CVE-2015-3196");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-05-10 10:17:46 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2016-01-11 17:41:42 +0530 (Mon, 11 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL DoS Vulnerability (20151203) - Linux");

  script_tag(name:"summary", value:"OpenSSL is prone to a Denial of Service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A race condition flaw exists in OpenSSL leading to a double free
  error due to improper handling of pre-shared key (PSK) identify hints.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to cause a
  DoS via a crafted ServerKeyExchange message.");

  script_tag(name:"affected", value:"OpenSSL version 1.0.0 before 1.0.0t, 1.0.1 before 1.0.1p, and
  1.0.2 before 1.0.2d.");

  script_tag(name:"solution", value:"Update to OpenSSL 1.0.0t, 1.0.1p, 1.0.2d or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://openssl.org/news/secadv/20151203.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

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

if(vers =~ "^1\.0\.0") {
  if(version_is_less(version:vers, test_version:"1.0.0t")) {
    fix = "1.0.0t";
    VULN = TRUE;
  }
}

else if(vers =~ "^1\.0\.1") {
  if(version_is_less(version:vers, test_version:"1.0.1p")) {
    fix = "1.0.1p";
    VULN = TRUE;
  }
}

else if(vers =~ "^1\.0\.2") {
  if(version_is_less(version:vers, test_version:"1.0.2d")) {
    fix = "1.0.2d";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
