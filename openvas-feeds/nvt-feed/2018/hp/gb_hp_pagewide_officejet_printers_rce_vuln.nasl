# Copyright (C) 2018 Greenbone Networks GmbH
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113093");
  script_version("2022-02-15T10:35:00+0000");
  script_tag(name:"last_modification", value:"2022-02-15 10:35:00 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2018-01-25 14:52:55 +0100 (Thu, 25 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-2741");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Pagewide and OfficeJet Printers RCE Vulnerability (Jan 2018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Gain a shell remotely");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"A potential security vulnerability has been identified with HP
  PageWide Printers and HP OfficeJet Pro Printers. This vulnerability could potentially be
  exploited to execute arbitrary code.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would give an attacker complete control
  over the target host.");

  script_tag(name:"affected", value:"Affected are following HP devices with a firmware version
  1707D or below:

  HP PageWide Managed MFP P57750dw

  HP PageWide Managed P55250 dw

  HP PageWide Pro MFP 577z

  HP PageWide Pro 552dw

  HP PageWide Pro MFP 577dw

  HP PageWide Pro MFP 477dw

  HP PageWide Pro 452dw

  HP PageWide Pro MFP 477dn

  HP PageWide Pro 452dn

  HP PageWide MFP 377dw

  HP PageWide 352dw

  HP OfficeJet Pro 8730 All-in-One Printer

  HP OfficeJet Pro 8740 All-in-One Printer

  HP OfficeJet Pro 8210 Printer

  HP OfficeJet Pro 8216 Printer

  HP OfficeJet Pro 8218 Printer");

  script_tag(name:"solution", value:"Update to firmware version 1708D or above.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c05462914");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42176/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:hp:pagewide_mfp_p57750_firmware",
                     "cpe:/o:hp:pagewide_p55250_firmware",
                     "cpe:/o:hp:pagewide_pro_577_mfp_firmware",
                     "cpe:/o:hp:pagewide_pro_552_firmware",
                     "cpe:/o:hp:pagewide_pro_577_mfp_firmware",
                     "cpe:/o:hp:pagewide_pro_477dw_mfp_firmware",
                     "cpe:/o:hp:pagewide_pro_452dw_firmware",
                     "cpe:/o:hp:pagewide_pro_477dn_mfp_firmware",
                     "cpe:/o:hp:pagewide_pro_452dn_firmware",
                     "cpe:/o:hp:pagewide_377dw_mfp_firmware",
                     "cpe:/o:hp:pagewide_352dw_firmware",
                     "cpe:/o:hp:officejet_pro_8730_firmware",
                     "cpe:/o:hp:officejet_pro_8740_firmware",
                     "cpe:/o:hp:officejet_pro_8210_firmware",
                     "cpe:/o:hp:officejet_pro_8216_firmware",
                     "cpe:/o:hp:officejet_pro_8218_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = toupper(infos["version"]);

# e.g. WEBPDLPP1N001.2107A.00
version = split(version, sep: ".", keep: FALSE);
if (!isnull(version[1])) {
  version = version[1];
  if (version_is_less(version: version, test_version: "1708D")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1708D");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
