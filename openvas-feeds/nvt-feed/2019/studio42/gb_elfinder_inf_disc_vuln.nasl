# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113324");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-01-11 13:42:31 +0200 (Fri, 11 Jan 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 12:47:00 +0000 (Thu, 09 Sep 2021)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-5884");

  script_name("elFinder <= 2.1.44 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elfinder_detect.nasl");
  script_mandatory_keys("studio42/elfinder/detected");

  script_tag(name:"summary", value:"elFinder is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability affects installations with the PHP curl extension enabled
  and safe_mode and open_basedir not set.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access sensitive information.");
  script_tag(name:"affected", value:"elFinder through version 2.1.44.");
  script_tag(name:"solution", value:"Update to version 2.1.45.");

  script_xref(name:"URL", value:"https://github.com/Studio-42/elFinder/commit/f133163f2d754584de65d718b2fde96191557316");
  script_xref(name:"URL", value:"https://github.com/Studio-42/elFinder/releases/tag/2.1.45");

  exit(0);
}

CPE = "cpe:/a:std42:elfinder";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2.1.45" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.45" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
