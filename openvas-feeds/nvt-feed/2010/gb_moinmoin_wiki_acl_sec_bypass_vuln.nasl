# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moinmo:moinmoin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902154");
  script_version("2025-03-05T05:38:52+0000");
  script_cve_id("CVE-2009-4762");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-04-01 11:04:35 +0200 (Thu, 01 Apr 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MoinMoin Wiki Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl");
  script_mandatory_keys("moinmoinWiki/installed");

  script_xref(name:"URL", value:"http://moinmo.in/SecurityFixes");
  script_xref(name:"URL", value:"http://hg.moinmo.in/moin/1.8/rev/897cdbe9e8f2");
  script_xref(name:"URL", value:"http://hg.moinmo.in/moin/1.7/rev/897cdbe9e8f2");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0266");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass intended access
  restrictions by requesting an item.");
  script_tag(name:"affected", value:"MoinMoin Wiki version 1.7.x before 1.7.3 and 1.8.x before 1.8.3");
  script_tag(name:"insight", value:"The flaw is due to error in checking the parent ACLs in certain
  inappropriate circumstances during processing of hierarchical ACLs.");
  script_tag(name:"solution", value:"Upgrade to MoinMoin Wiki 1.7.3 or 1.8.3.");
  script_tag(name:"summary", value:"MoinMoin Wiki is prone to a security bypass vulnerability.");

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

if( version_in_range( version:vers, test_version:"1.7", test_version2:"1.7.2" ) ||
    version_in_range( version:vers, test_version:"1.8", test_version2:"1.8.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.7.3/1.8.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
