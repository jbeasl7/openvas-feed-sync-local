# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imatix:xitami:server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900548");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-05-06 08:04:28 +0200 (Wed, 06 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6519", "CVE-2008-6520");
  script_name("Xitami Multiple Format String Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_xitami_server_detect.nasl");
  script_mandatory_keys("xitami/version");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5354");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/28603");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/41644");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/41645");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code and can lead to application crash.");

  script_tag(name:"affected", value:"Xitami version 2.5c2 and prior.");

  script_tag(name:"insight", value:"- Error exists while handling a format string specifiers in a Long Running
  Web Process (LRWP) request, which triggers incorrect logging code involving
  the sendfmt function in the SMT kernel.

  - Error in Server Side Includes (SSI) filter when processes requests with
  specially crafted URIs ending in .ssi, .shtm, or .shtml, which triggers
  incorrect logging code involving the sendfmt function in the SMT kernel.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Xitami web server is prone to multiple format string vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2.5c2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"WillNotFix" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );