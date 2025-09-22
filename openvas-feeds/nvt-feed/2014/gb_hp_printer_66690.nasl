# Copyright (C) 2014 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105040");
  script_version("2022-10-11T10:12:36+0000");
  script_tag(name:"last_modification", value:"2022-10-11 10:12:36 +0000 (Tue, 11 Oct 2022)");
  script_tag(name:"creation_date", value:"2014-06-03 16:01:41 +0200 (Tue, 03 Jun 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:29:00 +0000 (Thu, 15 Oct 2020)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0160");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printers Information Disclosure Vulnerability (Apr 2014, Heartbleed)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"A potential security vulnerability has been identified in HP
  Officejet Pro X printers and in certain Officejet Pro printers running OpenSSL. This is the
  OpenSSL vulnerability known as 'Heartbleed' (CVE-2014-0160) which could be exploited remotely
  resulting in disclosure of information.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to gain access to sensitive
  information that may aid in further attacks.");

  script_tag(name:"affected", value:"HP Officejet Pro X451dn < BNP1CN1409BR

  HP Officejet Pro X451dw  < BWP1CN1409BR

  HP Officejet Pro X551dw  < BZP1CN1409BR

  HP Officejet Pro X476dn  < LNP1CN1409BR

  HP Officejet Pro X476dw  < LWP1CN1409BR

  HP Officejet Pro X576dw  < LZP1CN1409BR

  HP Officejet Pro 276dw   < FRP1CN1416BR

  HP Officejet Pro 251dw   < EVP1CN1416BR

  HP Officejet Pro 8610    < FDP1CN1416AR

  HP Officejet Pro 8615    < FDP1CN1416AR

  HP Officejet Pro 8620    < FDP1CN1416AR

  HP Officejet Pro 8625    < FDP1CN1416AR

  HP Officejet Pro 8630    < FDP1CN1416AR

  HP Officejet Pro 8640    < FDP1CN1416AR

  HP Officejet Pro 8660    < FDP1CN1416AR");

  script_tag(name:"solution", value:"Please see the references or vendor advisory for possible
  solutions.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/531993");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:hp:officejet_pro_x451dn_firmware",
                     "cpe:/o:hp:officejet_pro_x451dw_firmware",
                     "cpe:/o:hp:officejet_pro_x551dw_firmware",
                     "cpe:/o:hp:officejet_pro_x476dn_mfp_firmware",
                     "cpe:/o:hp:officejet_pro_x476dw_mfp_firmware",
                     "cpe:/o:hp:officejet_pro_x576dw_mfp_firmware",
                     "cpe:/o:hp:officejet_pro_276dw_mfp_firmware",
                     "cpe:/o:hp:officejet_pro_251dw_firmware",
                     "cpe:/o:hp:officejet_pro_8610_firmware",
                     "cpe:/o:hp:officejet_pro_8615_firmware",
                     "cpe:/o:hp:officejet_pro_8620_firmware",
                     "cpe:/o:hp:officejet_pro_8625_firmware",
                     "cpe:/o:hp:officejet_pro_8630_firmware",
                     "cpe:/o:hp:officejet_pro_8640_firmware",
                     "cpe:/o:hp:officejet_pro_8660_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

if (cpe == "cpe:/o:hp:officejet_pro_x451dn_firmware") {
  if (version_is_less(version: version, test_version: "BNP1CN1409BR")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "BNP1CN1409BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:officejet_pro_x451dw_firmware") {
  if (version_is_less(version: version, test_version: "BWP1CN1409BR")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "BWP1CN1409BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:officejet_pro_x551dw_firmware") {
  if (version_is_less(version: version, test_version: "BZP1CN1409BR")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "BZP1CN1409BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:officejet_pro_x476dn_mfp_firmware") {
  if (version_is_less(version: version, test_version: "LNP1CN1409BR")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LNP1CN1409BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:officejet_pro_x476dw_mfp_firmware") {
  if (version_is_less(version: version, test_version: "LWP1CN1409BR")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LWP1CN1409BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:officejet_pro_x576dw_mfp_firmware") {
  if (version_is_less(version: version, test_version: "LZP1CN1409BR")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "LZP1CN1409BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:officejet_pro_276dw_mfp_firmware") {
  if (version_is_less(version: version, test_version: "FRP1CN1416BR")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "FRP1CN1416BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:officejet_pro_251dw_firmware") {
  if (version_is_less(version: version, test_version: "EVP1CN1416BR")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "EVP1CN1416BR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:hp:officejet_pro_86(10|15|20|25|30|40|60)") {
  if (version_is_less(version: version, test_version: "FDP1CN1416AR")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "FDP1CN1416AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
