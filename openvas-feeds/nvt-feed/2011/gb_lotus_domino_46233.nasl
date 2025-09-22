# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103066");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-02-08 13:20:01 +0100 (Tue, 08 Feb 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("IBM Lotus Domino Server 'diiop' Multiple RCE Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46233");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-052/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-053/");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  script_tag(name:"impact", value:"Successfully exploiting these issues may allow remote attackers to
  execute arbitrary code in the context of the Lotus Domino server process. Failed attacks will cause
  denial-of-service conditions.");

  script_tag(name:"summary", value:"IBM Lotus Domino server is prone to multiple remote code-execution
  vulnerabilities because it fails to perform adequate boundary checks on user-supplied input.");

  script_tag(name:"solution", value:"Update to version 8.5.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit(0);

if( version_is_less( version:version, test_version:"8.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"8.5.3" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
