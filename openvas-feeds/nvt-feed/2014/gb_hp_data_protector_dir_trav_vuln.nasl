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

CPE = "cpe:/a:hp:data_protector";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103975");
  script_version("2022-09-20T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-20 10:11:40 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"creation_date", value:"2014-02-11 11:34:29 +0700 (Tue, 11 Feb 2014)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2013-6194");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP (OpenView Storage) Data Protector Backup Client Service Directory Traversal");

  script_category(ACT_GATHER_INFO);

  script_family("General");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("hp_data_protector_installed.nasl");
  script_mandatory_keys("microfocus/data_protector/detected");

  script_tag(name:"impact", value:"A remote attacker can upload and execute arbitrary code.");

  script_tag(name:"affected", value:"HP (OpenView Storage) Data Protector 6.21 and prior.");

  script_tag(name:"insight", value:"There is a directory traversal vulnerability in HP
  (OpenView Storage) Data Protector. The vulnerability is in the backup client service when parsing
  packets with opcode 42.");

  script_tag(name:"summary", value:"HP (OpenView Storage) Data Protector is prone to a directory
  traversal vulnerability which might lead to execution of arbitrary code.");

  script_tag(name:"solution", value:"Apply the patch from the referenced link or update to a newer
  version.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c03822422");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31181/");
  script_xref(name:"URL", value:"https://ovrd.external.hp.com/hpp/hpp2rd");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"06.21" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"06.22" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
