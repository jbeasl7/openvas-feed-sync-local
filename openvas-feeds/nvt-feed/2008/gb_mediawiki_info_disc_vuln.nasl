# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900422");
  script_version("2024-07-19T15:39:06+0000");
  script_cve_id("CVE-2008-5687", "CVE-2008-5688");
  script_tag(name:"last_modification", value:"2024-07-19 15:39:06 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("MediaWiki 1.8.1 - 1.13.3 Information Disclosure Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl");
  script_mandatory_keys("mediawiki/detected");

  script_xref(name:"URL", value:"http://www.mediawiki.org/wiki/Manual:$wgShowExceptionDetails");
  script_xref(name:"URL", value:"http://lists.wikimedia.org/pipermail/mediawiki-announce/2008-December/000080.html");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple information disclosure
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to:

  - wgShowExceptionDetails variable sometimes shows the installation path of MediaWiki which can
  lead to expose sensitive information about the remote system.

  - fails to protect against the download of backups of deleted images in images/deleted/.");

  script_tag(name:"impact", value:"Successful exploitation will lead to gain knowledge on sensitive
  directories on the remote web server via requests.");

  script_tag(name:"affected", value:"MediaWiki versions 1.8.1 through 1.13.3.");

  script_tag(name:"solution", value:"Update to version 1.15.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"1.8.1", test_version2:"1.13.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.15.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
