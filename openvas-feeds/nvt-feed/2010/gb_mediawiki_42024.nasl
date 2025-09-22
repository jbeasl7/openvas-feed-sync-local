# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100732");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2010-2788");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("MediaWiki < 1.15.5 'profileinfo.php' XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_mediawiki_http_detect.nasl");
  script_mandatory_keys("mediawiki/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42024");
  script_xref(name:"URL", value:"http://lists.wikimedia.org/pipermail/mediawiki-announce/2010-July/000092.html");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site scripting (XSS) vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may let the
  attacker steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"MediaWiki versions prior to 1.15.5 and 1.16.0.");

  script_tag(name:"solution", value:"Update to version 1.15.5, 1.16.0 or later.");

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

if( version_is_less( version:vers, test_version:"1.15.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.15.5 or 1.16.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
