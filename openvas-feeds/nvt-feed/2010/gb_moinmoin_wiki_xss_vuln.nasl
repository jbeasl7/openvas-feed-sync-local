# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moinmo:moinmoin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801307");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2010-0828");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_name("MoinMoin 'Despam' Action Cross-Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl");
  script_mandatory_keys("moinmoinWiki/installed");

  script_xref(name:"URL", value:"http://moinmo.in/SecurityFixes");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39110");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39188");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=578801");
  script_xref(name:"URL", value:"http://comments.gmane.org/gmane.comp.security.oss.general/2773");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary scripting
  code.");
  script_tag(name:"affected", value:"MoinMoin Wiki version 1.8.7 and 1.9.2");
  script_tag(name:"insight", value:"Input passed via the 'page' name which is not properly sanitising before being
  returned to the user in 'Despam.py'. This can be exploited to insert arbitrary
  HTML and script code, when the Despam functionality is used on a page with a
  specially crafted page name.");
  script_tag(name:"solution", value:"Upgrade MoinMoin Wiki 1.9.2-3 or latest.");
  script_tag(name:"summary", value:"MoinMoin Wiki is prone to a cross-site scripting (XSS) vulnerability.");

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

if( version_is_equal( version:vers, test_version:"1.8.7" ) ||
    version_is_equal( version:vers, test_version:"1.9.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.9.2-3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
