# Copyright (C) 2010 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.801411");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_cve_id("CVE-2009-4897");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Ghostscript 'iscan.c' PDF Handling Remote Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40580");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41593");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60380");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_ghostscript_detect_win.nasl");
  script_mandatory_keys("artifex/ghostscript/win/detected");
  script_tag(name:"impact", value:"Successful exploitation allows the attackers to execute arbitrary code or
  cause a denial of service (memory corruption) via a crafted PDF document
  containing a long name.");
  script_tag(name:"affected", value:"Ghostscript version 8.64 and prior");
  script_tag(name:"insight", value:"The flaw is due to improper bounds checking by 'iscan.c' when
  processing malicious 'PDF' files, which leads to open a specially-crafted
  PDF file.");
  script_tag(name:"solution", value:"Upgrade to Ghostscript version 8.71 or later.");
  script_tag(name:"summary", value:"Ghostscript is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.ghostscript.com/");
  exit(0);
}

CPE = "cpe:/a:artifex:ghostscript";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "8.71" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.71", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
