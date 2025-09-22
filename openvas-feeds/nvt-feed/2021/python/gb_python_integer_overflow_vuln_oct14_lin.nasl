# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118258");
  script_version("2024-02-22T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-22 05:06:55 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2021-11-01 11:45:13 +0100 (Mon, 01 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_cve_id("CVE-2014-7185");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 2.7.8 Integer Overflow Vulnerability (Oct 2014) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to an integer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the user-supplied input is not properly
  validated when handling large buffer sizes and/or offsets.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  access to potentially sensitive information or cause a denial of service.");

  script_tag(name:"affected", value:"Python 2.7.x before version 2.7.8.");

  script_tag(name:"solution", value:"Update to version 2.7.8 or later.");

  script_xref(name:"URL", value:"http://bugs.python.org/issue2183");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/96193");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version:version, test_version:"2.7", test_version2:"2.7.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.8", install_path:location );
  security_message( port:port, data:report);
  exit( 0 );
}

exit( 99 );
