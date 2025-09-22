# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:openview_network_node_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103026");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2011-0261", "CVE-2011-0262", "CVE-2011-0263", "CVE-2011-0264", "CVE-2011-0265", "CVE-2011-0266", "CVE-2011-0267", "CVE-2011-0268", "CVE-2011-0269", "CVE-2011-0270", "CVE-2011-0271");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-01-13 13:28:59 +0100 (Thu, 13 Jan 2011)");
  script_name("HP OpenView Network Node Manager Multiple RCE Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("secpod_hp_openview_nnm_detect.nasl");
  script_mandatory_keys("HP/OVNNM/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45762");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/515628");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-003/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-004/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-005/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-006/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-007/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-008/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-009/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-010/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-011/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-012/");

  script_tag(name:"summary", value:"HP OpenView Network Node Manager is prone to multiple remote code-
  execution vulnerabilities.");
  script_tag(name:"affected", value:"OpenView Network Node Manager 7.51 and 7.53 are vulnerable.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"impact", value:"Successful exploits may allow an attacker to execute arbitrary code
  with the privileges of the user running the application's webserver. Failed exploit
  attempts will likely result in denial-of-service conditions.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_version( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! vers = get_kb_item( "www/"+ port + "/HP/OVNNM/Ver" ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"B.07.51" ) ||
    version_is_equal( version:vers, test_version:"B.07.53" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
