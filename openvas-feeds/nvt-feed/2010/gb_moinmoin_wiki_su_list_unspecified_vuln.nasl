# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moinmo:moinmoin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800173");
  script_version("2024-03-04T05:10:24+0000");
  script_cve_id("CVE-2010-0668");
  script_tag(name:"last_modification", value:"2024-03-04 05:10:24 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("MoinMoin Wiki Superuser Lists Unspecified Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl");
  script_mandatory_keys("moinmoinWiki/installed");

  script_xref(name:"URL", value:"http://moinmo.in/SecurityFixes");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38023");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38444");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56002");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0266");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/02/15/2");

  script_tag(name:"impact", value:"Impact is currently unknown.");
  script_tag(name:"affected", value:"MoinMoin Wiki version 1.5.x through 1.7.x, 1.8.x before 1.8.7,
  and 1.9.x before 1.9.2 on all platforms.");
  script_tag(name:"insight", value:"Unspecified error is present related to configurations that have a non-empty
  superuser list, when 'xmlrpc', 'SyncPages' actions are enabled or OpenID
  configured.");
  script_tag(name:"solution", value:"Upgrade to MoinMoin Wiki 1.8.7 or 1.9.2.");
  script_tag(name:"summary", value:"MoinMoin Wiki is prone to unspecified vulnerabilities.");

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

## 1.9 before 1.9.2
if( version_in_range( version:vers, test_version:"1.5", test_version2:"1.7.9" ) ||
    version_in_range( version:vers, test_version:"1.8", test_version2:"1.8.6" ) ||
    version_in_range( version:vers, test_version:"1.9", test_version2:"1.9.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.8.7/1.9.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
