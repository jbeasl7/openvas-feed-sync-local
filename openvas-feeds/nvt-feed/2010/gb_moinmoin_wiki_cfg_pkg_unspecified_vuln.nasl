# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:moinmo:moinmoin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800174");
  script_version("2024-03-01T14:37:10+0000");
  script_cve_id("CVE-2010-0717");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MoinMoin Wiki 'cfg' Package Configuration Unspecified Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl");
  script_mandatory_keys("moinmoinWiki/installed");

  script_xref(name:"URL", value:"http://moinmo.in/SecurityFixes");
  script_xref(name:"URL", value:"http://moinmo.in/MoinMoinRelease1.8");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/02/15/2");
  script_xref(name:"URL", value:"http://moinmo.in/SecurityFixes/AdvisoryForDistributors");

  script_tag(name:"impact", value:"Impack is currently unknown.");
  script_tag(name:"affected", value:"MoinMoin Wiki version before 1.8.7 on all platforms.");
  script_tag(name:"insight", value:"The flaw is due to default configuration of 'cfg' package which does not
  prevent unsafe package actions causing unspecified impact.");
  script_tag(name:"solution", value:"Upgrade to MoinMoin Wiki 1.8.7 or later");
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

if( version_is_less( version:vers, test_version:"1.8.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.8.7" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
