# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112362");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2018-12115");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-20 21:15:00 +0000 (Fri, 20 Mar 2020)");
  script_tag(name:"creation_date", value:"2018-08-27 14:13:00 +0200 (Mon, 27 Aug 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Node.js < 10.9.0, < 8.11.4, < 6.14.4 OOB Write Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"Node.js is prone to an out-of-bounds write vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An OOB write in Buffer can be used to write to memory outside of a Buffer's memory space.
This can corrupt unrelated Buffer objects or cause the Node.js process to crash.

When used with UCS-2 encoding (recognized by Node.js under the names 'ucs2', 'ucs-2', 'utf16le' and 'utf-16le'), Buffer#write() can be abused
to write outside of the bounds of a single Buffer. Writes that start from the second-to-last position of a buffer cause a miscalculation of the maximum length of the input bytes to be written.");

  script_tag(name:"affected", value:"Node.js versions 6.x prior to 6.14.4, 8.x prior to 8.11.4 and 10.x prior to 10.9.0.");

  script_tag(name:"solution", value:"Upgrade to Node.js version 6.14.4, 8.11.4 or 10.9.0 respectively.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/august-2018-security-releases");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105127");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_nodejs_detect_macosx.nasl");
  script_mandatory_keys("Nodejs/MacOSX/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_in_range( version:version, test_version:"6.0", test_version2:"6.14.3" ) ) {
  fix = "6.14.4";
}

if( version_in_range( version:version, test_version:"8.0", test_version2:"8.11.3" ) ) {
  fix = "8.11.4";
}

if( version =~ "^10\." && version_is_less( version:version, test_version:"10.9.0" ) ) {
  fix = "10.9.0";
}

if( fix ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
