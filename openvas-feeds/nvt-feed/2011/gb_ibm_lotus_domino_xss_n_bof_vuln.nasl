# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902572");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2011-3575", "CVE-2011-3576");

  script_name("IBM Lotus Domino Cross Site Scripting and Buffer Overflow Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code with system-level privileges or steal cookie-based authentication
  credentials and launch other attacks.");

  script_tag(name:"affected", value:"IBM Lotus Domino Versions 8.5.2 and prior.");

  script_tag(name:"insight", value:"- Input passed via the 'PanelIcon' parameter in an
  fmpgPanelHeader ReadForm action to WebAdmin.nsf is not properly sanitised
  before being returned to the user. This can be exploited to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.

  - Stack-based buffer overflow error in the NSFComputeEvaluateExt function
  in Nnotes.dll allows remote authenticated users to execute arbitrary code
  via a long 'tHPRAgentName' parameter in an fmHttpPostRequest OpenForm
  action to WebAdmin.nsf.");

  script_tag(name:"solution", value:"Upgrade to IBM Lotus Domino Versions 8.5.2 FP2, 8.5.3 or later.");

  script_tag(name:"summary", value:"IBM Lotus Domino Server is prone to cross-site scripting and buffer overflow
  vulnerabilities.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69802");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49701");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49705");
  script_xref(name:"URL", value:"http://www.research.reversingcode.com/index.php/advisories/73-ibm-ssd-1012211");
  script_xref(name:"URL", value:"http://www.research.reversingcode.com/exploits/IBMLotusDomino_StackOverflowPoC");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"8.5.2.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.5.2 FP2" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
