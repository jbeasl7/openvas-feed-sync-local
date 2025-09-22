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

CPE = "cpe:/a:matrixssl:matrixssl";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106347");
  script_version("2023-01-18T10:11:02+0000");
  script_tag(name:"last_modification", value:"2023-01-18 10:11:02 +0000 (Wed, 18 Jan 2023)");
  script_tag(name:"creation_date", value:"2016-10-12 11:13:38 +0700 (Wed, 12 Oct 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-06 15:14:00 +0000 (Fri, 06 Jan 2017)");

  script_cve_id("CVE-2016-6890", "CVE-2016-6891", "CVE-2016-6892", "CVE-2016-6882", "CVE-2016-6883",
                "CVE-2016-6884");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MatrixSSL <= 3.8.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_matrixssl_http_detect.nasl");
  script_mandatory_keys("matrixssl/detected");

  script_tag(name:"summary", value:"MatrixSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2016-6890 (Heap-based Buffer Overflow): The Subject Alt Name field of X.509 certificates is
  not properly parsed. A specially crafted certificate may result in a heap-based buffer overflow
  and arbitrary code execution.

  - CVE-2016-6891 (Improper Restriction of Operations within the Bounds of a Memory Buffer): The
  ASN.1 Bit Field is not properly parsed. A specially crafted certificate may lead to a denial of
  service condition due to an out of bounds read in memory.

  - CVE-2016-6892 (Free of Memory not on the Heap): The x509FreeExtensions() function does not
  properly parse X.509 certificates. A specially crafted certificate may cause a free operation on
  unallocated memory, resulting in a denial of service condition.");

  script_tag(name:"impact", value:"A remote, unauthenticated attacker may be able to create a denial
  of service condition or execute arbitrary code in the context of the SSL stack.");

  script_tag(name:"affected", value:"MatrixSSL 3.8.5 and prior.");

  script_tag(name:"solution", value:"Update to version 3.8.6 or later.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/396440");
  script_xref(name:"URL", value:"http://www.tripwire.com/state-of-security/security-data-protection/cyber-security/flawed-matrixssl-code-highlights-need-for-better-iot-update-practices/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.8.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
