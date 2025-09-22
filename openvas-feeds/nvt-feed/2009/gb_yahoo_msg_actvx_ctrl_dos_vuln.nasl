# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801150");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-4171");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37007");
  script_name("Yahoo! Messenger 'YahooBridgeLib.dll' ActiveX Control DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_yahoo_msg_detect.nasl");
  script_mandatory_keys("YahooMessenger/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause Denial of
  Service condition on the affected application.");

  script_tag(name:"affected", value:"Yahoo! Messenger version 9.x to 9.0.0.2162 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to a NULL pointer dereference error in 'RegisterMe()' method
  in 'YahooBridgeLib.dll', which can be exploited by causing the victim to visit a specially crafted web page.");

  script_tag(name:"solution", value:"Upgrade to Yahoo! Messenger version 10.0.0.1270 or later");

  script_tag(name:"summary", value:"Yahoo! Messenger is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("version_func.inc");

if( ! vers = get_kb_item( "YahooMessenger/Ver" ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"9.0", test_version2:"9.0.0.2162" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.0.0.1270" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
