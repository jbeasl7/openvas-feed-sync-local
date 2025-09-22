# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112364");
  script_version("2024-02-29T05:05:39+0000");
  script_cve_id("CVE-2018-7166");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-29 05:05:39 +0000 (Thu, 29 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-22 13:59:00 +0000 (Tue, 22 Sep 2020)");
  script_tag(name:"creation_date", value:"2018-08-27 14:37:00 +0200 (Mon, 27 Aug 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Node.js 10.x < 10.9.0 Unintentional Exposure of Uninitialized Memory Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"Node.js is prone to an unintentional exposure of uninitialized memory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is an argument processing flaw that causes Buffer.alloc() to return uninitialized memory.
This method is intended to be safe and only return initialized, or cleared, memory. The third argument specifying encoding can be passed as a number,
this is misinterpreted by Buffer's internal 'fill' method as the start to a fill operation.

This flaw may be abused where Buffer.alloc()
arguments are derived from user input to return uncleared memory blocks that may contain sensitive information.");

  script_tag(name:"affected", value:"Node.js version 10.x prior to 10.9.0.");

  script_tag(name:"solution", value:"Update to version 10.9.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/august-2018-security-releases");

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

if( version =~ "^10\." && version_is_less( version:version, test_version:"10.9.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.9.0", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
