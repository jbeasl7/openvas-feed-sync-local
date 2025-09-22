# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:twiki:twiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801281");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2009-4898");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("TWiki Cross-Site Request Forgery Vulnerability (Sep 2010)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_twiki_detect.nasl");
  script_mandatory_keys("twiki/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain administrative
  privileges on the target application and can cause CSRF attack.");

  script_tag(name:"affected", value:"TWiki version prior to 4.3.2");

  script_tag(name:"insight", value:"Attack can be done by tricking an authenticated TWiki user into visiting
  a static HTML page on another side, where a Javascript enabled browser will send an HTTP POST request
  to TWiki, which in turn will process the request as the TWiki user.");

  script_tag(name:"solution", value:"Upgrade to TWiki version 4.3.2 or later.");

  script_tag(name:"summary", value:"TWiki is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/08/03/8");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/08/02/17");
  script_xref(name:"URL", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAuditTokenBasedCsrfFix");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://twiki.org/cgi-bin/view/Codev/DownloadTWiki");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"4.3.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.3.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
