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

CPE = "cpe:/o:paloaltonetworks:pan-os";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106882");
  script_version("2022-11-16T10:12:35+0000");
  script_tag(name:"last_modification", value:"2022-11-16 10:12:35 +0000 (Wed, 16 Nov 2022)");
  script_tag(name:"creation_date", value:"2017-06-20 09:10:58 +0700 (Tue, 20 Jun 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 20:19:00 +0000 (Thu, 03 Nov 2022)");

  script_cve_id("CVE-2016-10229");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Palo Alto PAN-OS Kernel Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Palo Alto PAN-OS Local Security Checks");
  script_dependencies("gb_paloalto_panos_consolidation.nasl");
  script_mandatory_keys("palo_alto_pan_os/version");

  script_tag(name:"summary", value:"A vulnerability exists in the Linux kernel of PAN-OS that may result in
Remote Code Execution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in the Linux kernel networking subsystem for UDP could
enable an attacker to execute arbitrary code within the context of the kernel. The Data Plane (DP) of PAN-OS is
not affected by this issue since it does not use the vulnerable Linux kernel code.");

  script_tag(name:"affected", value:"PAN-OS 6.1.17 and earlier, PAN-OS 7.0, PAN-OS 7.1.10 and earlier, PAN-OS
8.0.2 and earlier.");

  script_tag(name:"solution", value:"Update to PAN-OS 6.1.18, 7.1.11, 8.0.3 and later.");

  script_xref(name:"URL", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/88");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

model = get_kb_item("palo_alto_pan_os/model");

if (version_is_less(version: version, test_version: "6.1.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.18");

  if (model)
    report += '\nModel:             ' + model;

  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.1.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.11");

  if (model)
    report += '\nModel:             ' + model;

  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.3");

  if (model)
    report += '\nModel:             ' + model;

  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
