# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802129");
  script_version("2021-07-21T07:10:16+0000");
  script_cve_id("CVE-2011-2956");
  script_tag(name:"last_modification", value:"2021-07-21 07:10:16 +0000 (Wed, 21 Jul 2021)");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("AzeoTech DAQFactory < 5.85 Build 1842 DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"https://us-cert.cisa.gov/ics/advisories/ICSA-11-122-01");

  script_tag(name:"summary", value:"AzeoTech DAQFactory is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  DoS (system reboot or shutdown).");

  script_tag(name:"affected", value:"AzeoTech DAQFactory version prior to 5.85 Build 1842.");

  script_tag(name:"insight", value:"The flaw exists due to error in application, which fails to
  perform authentication for certain signals.");

  script_tag(name:"solution", value:"Update to version 5.85 Build 1842 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\DAQFactoryExpress"))
  exit(0);

path = registry_get_sz(key:"SOFTWARE\DAQFactoryExpress", item:"Installation Path");
if(!path)
  exit(0);

vers = fetch_file_version(sysPath:path, file_name:"DAQFactoryExpress.exe");
if(!vers)
  exit(0);

if(version_is_less(version:vers, test_version:"5.85.1842.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.85.1842.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);