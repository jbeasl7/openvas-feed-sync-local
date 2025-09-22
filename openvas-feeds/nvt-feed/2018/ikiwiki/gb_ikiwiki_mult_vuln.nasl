# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113159");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-04-18 13:10:35 +0200 (Wed, 18 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-22 15:57:00 +0000 (Tue, 22 May 2018)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2016-9645", "CVE-2016-9646");

  script_name("IkiWiki Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ikiwiki_consolidation.nasl");
  script_mandatory_keys("ikiwiki/detected");

  script_tag(name:"summary", value:"The fix for ikiwiki for CVE-2016-10026 was incomplete
  resulting in editing restriction bypass for git revert when using git versions older than 2.8.0.

  ikiwiki incorrectly called the CGI::FormBuilder->field method (similar to the CGI->param API that led to Bugzilla's CVE-2014-1572),
  which can be abused to lead to commit metadata forgery.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to bypass access restriction.");
  script_tag(name:"affected", value:"IkiWiki before version 3.20161229.");
  script_tag(name:"solution", value:"Update to version 3.20161229.");

  script_xref(name:"URL", value:"https://ikiwiki.info/security/#cve-2016-9645");
  script_xref(name:"URL", value:"https://ikiwiki.info/security/#cve-2016-9646");

  exit(0);
}

CPE = "cpe:/a:ikiwiki:ikiwiki";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "3.20161229" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.20161229" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
