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

CPE = "cpe:/a:ibm:tivoli_storage_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811060");
  script_version("2022-12-13T10:10:56+0000");
  script_cve_id("CVE-2016-6110");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-12-13 10:10:56 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-25 01:29:00 +0000 (Thu, 25 May 2017)");
  script_tag(name:"creation_date", value:"2017-06-02 15:14:22 +0530 (Fri, 02 Jun 2017)");
  script_name("IBM TSM Client 'vCenter Password' Information Disclosure Vulnerability - Windows");

  script_tag(name:"summary", value:"IBM Tivoli Storage Manager Client is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists during VM backup with the
  INCLUDE.VMTSMVSS option when application tracing is enabled with VMTSMVSS flag.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  user to get the unencrypted login credentials to VMware vCenter.");

  script_tag(name:"affected", value:"IBM Tivoli Storage Manager Client versions 7.1.0.0
  through 7.1.6.3.");

  script_tag(name:"solution", value:"Update to version 7.1.6.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21996198");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95306");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ibm_tsm_client_detect.nasl");
  script_mandatory_keys("IBM/Tivoli/Storage/Manager/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_in_range(version:vers, test_version:"7.1.0.0", test_version2:"7.1.6.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.1.6.4");
  security_message(data:report);
  exit(0);
}

exit(99);
