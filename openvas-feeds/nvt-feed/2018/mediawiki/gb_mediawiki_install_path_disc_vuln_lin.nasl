# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113163");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-04-19 15:06:33 +0200 (Thu, 19 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-18 17:08:00 +0000 (Fri, 18 May 2018)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-1686");

  script_name("MediaWiki 1.18.0 Installation Path Disclosure Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki allows remote attackers to obtain the installation path via vectors related to thumbnail creation.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"MediaWiki through version 1.18.0");
  script_tag(name:"solution", value:"Update to MedaiWiki 1.27.4 or above.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Mar/102");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66141");
  script_xref(name:"URL", value:"https://www.mediawiki.org/wiki/Download");

  exit(0);
}

CPE = "cpe:/a:mediawiki:mediawiki";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "1.18.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.27.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
