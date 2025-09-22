# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:wac_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900924");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-7031");
  script_name("Foxit WAC Server Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_foxit_wac_server_detect.nasl");
  script_mandatory_keys("Foxit-WAC-Server/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/28272/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27873");
  script_xref(name:"URL", value:"http://aluigi.org/adv/wachof-adv.txt");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/40608");

  script_tag(name:"impact", value:"Successful exploitation will let the attackers execute arbitrary
  code and crash the application to cause denial of service.");

  script_tag(name:"affected", value:"Foxit WAC Server 2.0 Build 3503 and prior on Windows.");

  script_tag(name:"insight", value:"A heap-based buffer-overflow occurs in the 'wacsvr.exe' while
  processing overly long packets sent to SSH/Telnet ports.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Foxit WAC Server is prone to a buffer overflow vulnerability.");

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

if( version_is_less_equal( version:vers, test_version:"2.0.3503" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None available" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
