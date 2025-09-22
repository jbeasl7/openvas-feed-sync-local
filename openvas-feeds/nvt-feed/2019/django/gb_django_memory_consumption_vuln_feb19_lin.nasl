# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113344");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-02-26 14:37:01 +0200 (Tue, 26 Feb 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod", value:"30");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-6975");

  script_name("Django < 2.16 Uncontrolled Memory Consumption Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to an uncontrolled memory consumption vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"If django.utils.numberformat.format() received a Decimal with a large number
  of digits or a large exponent, it could lead to significant memory usage
  due to a call to .format().");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to exhaust the target system's
  resources and crash the affected and other applications.");
  script_tag(name:"affected", value:"Django through version 1.11.18, version 2.0.0 through 2.0.10 and 2.1.0 through 2.1.5.");
  script_tag(name:"solution", value:"Update to version 1.11.19, 2.0.11 or 2.1.6 respectively.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2019/feb/11/security-releases/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/106964");

  exit(0);
}

CPE = "cpe:/a:djangoproject:django";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "1.11.19" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.11.19" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.0.0", test_version2: "2.0.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.11" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.1.0", test_version2: "2.1.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.6" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );