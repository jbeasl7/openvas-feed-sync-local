# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113264");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2018-09-07 10:11:44 +0200 (Fri, 07 Sep 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-26 13:55:00 +0000 (Fri, 26 Oct 2018)");

  script_cve_id("CVE-2018-1000658", "CVE-2018-1000659");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey <= 3.14.3 Multiple RCE Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/http/detected");

  script_tag(name:"summary", value:"LimeSurvey is prone to multiple remote code execution (RCE)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-1000658: An authenticated user uploading a zip archive containing malicious php files can result
    in the attacker gaining code execution via webshell

  - CVE-2018-1000659: An authenticated user uploading a specially crafted zip file can result
    in the attacker gaining remote code execution.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to gain complete control over
the target system.");

  script_tag(name:"affected", value:"LimeSurvey version 3.14.3 and prior.");

  script_tag(name:"solution", value:"Update to version 3.14.4.");

  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/commit/72a02ebaaf95a80e26127ee7ee2b123cccce05a7");
  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/commit/20fc85edccc80e7e7f162613542792380c44446a");
  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/commit/91d143230eb357260a19c8424b3005deb49a47f7");

  exit(0);
}

CPE = "cpe:/a:limesurvey:limesurvey";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "3.14.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.14.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
