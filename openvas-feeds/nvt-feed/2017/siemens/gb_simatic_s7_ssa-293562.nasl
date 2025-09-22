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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140312");
  script_version("2022-04-27T04:20:28+0000");
  script_tag(name:"last_modification", value:"2022-04-27 04:20:28 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-08-18 11:51:47 +0700 (Fri, 18 Aug 2017)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-15 18:15:00 +0000 (Mon, 15 Mar 2021)");

  script_cve_id("CVE-2017-2680", "CVE-2017-2681");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Siemens SIMATIC S7 PLC Multiple Vulnerabilities (SSA-293562)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_siemens_simatic_s7_consolidation.nasl");
  script_mandatory_keys("siemens/simatic_s7/detected", "siemens/simatic_s7/version");

  script_tag(name:"summary", value:"Siemens SIMATIC S7 devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-2680: Specially crafted PROFINET DCP broadcast packets could cause a denial-of-service
  condition of affected products on a local Ethernet segment (Layer 2). Human interaction is
  required to recover the systems. PROFIBUS interfaces are not affected.

  - CVE-2017-2681: Specially crafted PROFINET DCP packets sent on a local Ethernet segment (Layer 2)
  to an affected product could cause a denial-of-service condition in that product. Human
  interaction is required to recover the system. PROFIBUS interfaces are not affected.");

  script_tag(name:"impact", value:"A remote attacker may cause a DoS condition.");

  script_tag(name:"solution", value:"Siemens provides updated firmware versions. Please see the
  references for more information.");

  script_xref(name:"URL", value:"https://cert-portal.siemens.com/productcert/pdf/ssa-293562.pdf");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-129-02");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

model = get_kb_item("siemens/simatic_s7/model");

if (model !~ "^(12|15|3|4)[0-9]{2}")
  exit(0);

moduleType = get_kb_item("siemens/simatic_s7/modtype");

if (!fw = get_kb_item("siemens/simatic_s7/version"))
  exit(0);

if (model =~ "^3") {
  if ((moduleType =~ "^CPU 314C" || model =~ "^314C") && version_is_less(version: fw, test_version: "3.3.14")) {
    report = report_fixed_ver(installed_version: fw, fixed_version: "3.3.14");
    security_message(port: 0, data: report);
    exit(0);
  }

  if ((moduleType =~ "^CPU 3(15|17|19)" || model =~ "^3(15|17|19)") &&
      version_is_less(version: fw, test_version: "3.2.14")) {
    report = report_fixed_ver(installed_version: fw, fixed_version: "3.2.14");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (model =~ "^4") {
  if (moduleType =~ "^CPU 41(2|4|6|7)" && version_is_less(version: fw, test_version: "6.0.1")) {
    report = report_fixed_ver(installed_version: fw, fixed_version: "6.0.1");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (moduleType =~ "^CPU 410" && version_is_less(version: fw, test_version: "8.2.0")) {
    report = report_fixed_ver(installed_version: fw, fixed_version: "8.2.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if ((model == "1200" || moduleType =~ "^CPU.1200") && version_is_less(version: fw, test_version: "4.2")) {
  report = report_fixed_ver(installed_version: fw, fixed_version: "4.2");
  security_message(port: 0, data: report);
  exit(0);
}

if ((model == "1500" || moduleType =~ "^CPU.1500") && version_is_less(version: fw, test_version: "2.1.0")) {
  report = report_fixed_ver(installed_version: fw, fixed_version: "2.1.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
