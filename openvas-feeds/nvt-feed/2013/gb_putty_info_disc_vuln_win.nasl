# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:putty:putty";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803880");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-08-26 15:35:39 +0530 (Mon, 26 Aug 2013)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-4607");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PuTTY Information Disclosure Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_putty_portable_detect.nasl");
  script_mandatory_keys("putty/detected");

  script_tag(name:"summary", value:"PuTTY is prone to an information disclosure vulnerability.");

  script_tag(name:"insight", value:"The Flaw is due to improper handling of session passwords that
  were stored in the memory during the keyboard-interactive authentication");

  script_tag(name:"impact", value:"Successful exploitation will allow local attackers to read the
  passwords within the memory in clear text until the program stops running.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PuTTY versions 0.59 through 0.61 on Windows");

  script_tag(name:"solution", value:"Update to version 0.62 or later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2011/q4/500");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51021");
  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2011-4607");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/password-not-wiped.html");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version:version, test_version:"0.59", test_version2:"0.61" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"0.62", install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
