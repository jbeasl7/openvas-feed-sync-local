# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:mod_perl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100130");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-04-13 18:06:40 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0796");
  script_name("Apache mod_perl 'Apache::Status' and 'Apache2::Status' XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_apache_mod_perl_http_detect.nasl");
  script_mandatory_keys("apache/mod_perl/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34383");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/34cgt3cvybt86jsgmyc07ysf69cm62od");

  script_tag(name:"summary", value:"According to its version number, the remote version of the
  Apache mod_perl module is prone to a cross-site scripting (XSS) vulnerability because it fails to
  sufficiently sanitize user-supplied data.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"solution", value:"The vendor has released a fix through the SVN repository.
  Please see the references for more information.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"1.99" ) ||
    version_is_equal( version:vers, test_version:"1.3" ) ||
    version_is_equal( version:vers, test_version:"1.27" ) ||
    version_is_equal( version:vers, test_version:"1.29" ) ||
    version_in_range( version:vers, test_version:"2.0", test_version2:"2.0.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
