# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:thekelleys:dnsmasq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147385");
  script_version("2023-01-12T10:12:15+0000");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-01-11 03:13:09 +0000 (Tue, 11 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-11 17:51:00 +0000 (Tue, 11 Jan 2022)");

  script_cve_id("CVE-2021-45951", "CVE-2021-45952", "CVE-2021-45953", "CVE-2021-45954",
                "CVE-2021-45955", "CVE-2021-45956", "CVE-2021-45957", "CVE-2022-0934");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dnsmasq <= 2.86 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_dnsmasq_consolidation.nasl");
  script_mandatory_keys("thekelleys/dnsmasq/detected");

  script_tag(name:"summary", value:"Dnsmasq is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2021-45951: Heap-based buffer overflow in check_bad_address

  - CVE-2021-45952: Heap-based buffer overflow in dhcp_reply

  - CVE-2021-45953: Heap-based buffer overflow in extract_name

  - CVE-2021-45954: Heap-based buffer overflow in extract_name

  - CVE-2021-45955: Heap-based buffer overflow in resize_packet

  - CVE-2021-45956: Heap-based buffer overflow in print_mac

  - CVE-2021-45957: Heap-based buffer overflow in answer_request

  Note: The CVEs above have been changed to status 'DISPUTED'

  - CVE-2022-0934: Heap use after free in dhcp6_no_relay");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Dnsmasq version 2.86 and prior.");

  script_tag(name:"solution", value:"Update to version 2.87 or later.");

  script_xref(name:"URL", value:"https://github.com/google/oss-fuzz-vulns/blob/main/vulns/dnsmasq/OSV-2021-924.yaml");
  script_xref(name:"URL", value:"https://github.com/google/oss-fuzz-vulns/blob/main/vulns/dnsmasq/OSV-2021-927.yaml");
  script_xref(name:"URL", value:"https://github.com/google/oss-fuzz-vulns/blob/main/vulns/dnsmasq/OSV-2021-929.yaml");
  script_xref(name:"URL", value:"https://github.com/google/oss-fuzz-vulns/blob/main/vulns/dnsmasq/OSV-2021-931.yaml");
  script_xref(name:"URL", value:"https://github.com/google/oss-fuzz-vulns/blob/main/vulns/dnsmasq/OSV-2021-932.yaml");
  script_xref(name:"URL", value:"https://github.com/google/oss-fuzz-vulns/blob/main/vulns/dnsmasq/OSV-2021-933.yaml");
  script_xref(name:"URL", value:"https://github.com/google/oss-fuzz-vulns/blob/main/vulns/dnsmasq/OSV-2021-935.yaml");
  script_xref(name:"URL", value:"https://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2022q1/016272.html");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2022-0934");
  script_xref(name:"URL", value:"https://thekelleys.org.uk/dnsmasq/CHANGELOG");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.87")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.87", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
