# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143343");
  script_version("2021-09-06T11:58:24+0000");
  script_tag(name:"last_modification", value:"2021-09-06 11:58:24 +0000 (Mon, 06 Sep 2021)");
  script_tag(name:"creation_date", value:"2020-01-10 07:14:00 +0000 (Fri, 10 Jan 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-17184");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Xerox AltaLink Printers < 101.008.089.22600 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_xerox_printer_consolidation.nasl");
  script_mandatory_keys("xerox/printer/detected");

  script_tag(name:"summary", value:"Xerox AltaLink Printers are prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"affected", value:"Xerox AltaLink B80xx, C8030, C8035, C8045, C8055 and C8070 prior to
  firmware version 101.008.089.22600.");

  script_tag(name:"solution", value:"Update to version 101.008.089.22600 or later.");

  script_xref(name:"URL", value:"https://securitydocs.business.xerox.com/wp-content/uploads/2019/09/cert_Security_Mini_Bulletin_XRX19V_for_AltaLinkB80xx-C80xx-1.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:xerox:altalink_b8045_firmware",
                     "cpe:/o:xerox:altalink_b8055_firmware",
                     "cpe:/o:xerox:altalink_b8065_firmware",
                     "cpe:/o:xerox:altalink_b8075_firmware",
                     "cpe:/o:xerox:altalink_b8090_firmware",
                     "cpe:/o:xerox:altalink_c8030_firmware",
                     "cpe:/o:xerox:altalink_c8035_firmware",
                     "cpe:/o:xerox:altalink_c8045_firmware",
                     "cpe:/o:xerox:altalink_c8055_firmware",
                     "cpe:/o:xerox:altalink_c8070_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];

if (version_is_less(version: version, test_version: "101.008.089.22600")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "101.008.089.22600");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
