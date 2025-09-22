# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901109");
  script_version("2024-07-16T05:05:43+0000");
  script_cve_id("CVE-2010-1150");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("MediaWiki < 1.15.3, 1.16.x < 1.16.0beta2 'Login' CSRF Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl");
  script_mandatory_keys("mediawiki/detected");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=580418");
  script_xref(name:"URL", value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=23076");

  script_tag(name:"summary", value:"MediaWiki is prone to a cross-site request forgery (CSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of authenticated but
  unintended login attempt that allows attacker to conduct phishing attacks.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause CSRF attack
  and gain sensitive information.");

  script_tag(name:"affected", value:"MediaWiki versions prior to 1.15.3 and 1.16.x prior to
  1.16.0beta2.");

  script_tag(name:"solution", value:"Update to version 1.15.3, 1.16.0beta2 or later.");

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

if( version_is_less( version:vers, test_version:"1.15.3" ) ||
    version_in_range( version:vers, test_version:"1.16.0", test_version2:"1.16.0.beta1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.15.3 or 1.16.0.beta2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
