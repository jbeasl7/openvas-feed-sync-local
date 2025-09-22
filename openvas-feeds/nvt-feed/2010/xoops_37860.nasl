# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xoops:xoops";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100459");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-01-20 19:30:24 +0100 (Wed, 20 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("XOOPS Arbitrary File Deletion and HTTP Header Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("secpod_xoops_detect.nasl");
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37860");
  script_xref(name:"URL", value:"http://www.codescanlabs.com/research/advisories/xoops-2-4-3-vulnerability/");
  script_xref(name:"URL", value:"http://www.xoops.org");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/509034");

  script_tag(name:"summary", value:"XOOPS is prone to an HTTP-header-injection vulnerability and an arbitrary-file-
  deletion vulnerability.");

  script_tag(name:"insight", value:"By inserting arbitrary headers into an HTTP response, attackers may be
  able to launch various attacks, including cross-site request forgery,
  cross-site scripting, and HTTP-request smuggling.");

  script_tag(name:"impact", value:"Successful file-deletion exploits may corrupt data and cause denial-of-
  service conditions.");

  script_tag(name:"affected", value:"XOOPS 2.4.3 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this
  vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable
  respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2.4.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"WillNotFix" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
