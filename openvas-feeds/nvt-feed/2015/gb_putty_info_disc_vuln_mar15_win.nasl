# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:putty:putty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805434");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-03-31 13:05:20 +0530 (Tue, 31 Mar 2015)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2015-2157");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PuTTY Information Disclosure vulnerability (Mar 2015) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_putty_portable_detect.nasl");
  script_mandatory_keys("putty/detected");

  script_tag(name:"summary", value:"PuTTY is prone to an information disclosure vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to the program failing to
  clear SSH-2 private key information from the memory during the saving or
  loading of key files to disk.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local attacker
  to gain access to potentially sensitive information.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PuTTY version 0.51 through 0.63 on Windows.");

  script_tag(name:"solution", value:"Update to version 0.64 or later.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/02/28/4");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72825");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/private-key-not-wiped-2.html");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_in_range( version:version, test_version:"0.51", test_version2:"0.63" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"0.64", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
