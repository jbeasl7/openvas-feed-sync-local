# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117587");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"creation_date", value:"2021-07-19 12:38:23 +0000 (Mon, 19 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 12:15:00 +0000 (Wed, 16 Jun 2021)");

  script_cve_id("CVE-2014-3566", "CVE-2014-3567", "CVE-2014-3568");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenSSL Multiple Vulnerabilities (20141015) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist / mitigation has been implemented:

  - CVE-2014-3566: OpenSSL has added support for TLS_FALLBACK_SCSV to allow applications to block
  the ability for a MITM attacker to force a protocol downgrade. Some client applications (such as
  browsers) will reconnect using a downgraded protocol to work around interoperability bugs in older
  servers. This could be exploited by an active man-in-the-middle to downgrade connections to SSL
  3.0 even if both sides of the connection support higher protocols. SSL 3.0 contains a number of
  weaknesses including POODLE.

  - CVE-2014-3567: When an OpenSSL SSL/TLS/DTLS server receives a session ticket the integrity of
  that ticket is first verified. In the event of a session ticket integrity check failing, OpenSSL
  will fail to free memory causing a memory leak. By sending a large number of invalid session
  tickets an attacker could exploit this issue in a Denial Of Service attack.

  - CVE-2014-3568: When OpenSSL is configured with 'no-ssl3' as a build option, servers could accept
  and complete a SSL 3.0 handshake, and clients could be configured to send them.");

  script_tag(name:"affected", value:"OpenSSL version 0.9.8 through 0.9.8zb, 1.0.0 through 1.0.0n and
  1.0.1 through 1.0.1i.");

  script_tag(name:"solution", value:"Update to version 0.9.8zc, 1.0.0o, 1.0.1j or later.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20141015.txt");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_xref(name:"URL", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "0.9.8", test_version2: "0.9.8zb")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.9.8zc", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.0.0", test_version2: "1.0.0n")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.0o", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.0.1", test_version2: "1.0.1i")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.1j", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);