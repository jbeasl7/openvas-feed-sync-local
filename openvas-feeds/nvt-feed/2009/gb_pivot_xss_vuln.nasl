# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pivot:pivot";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900579");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2133", "CVE-2009-2134");
  script_name("Pivot <= 1.40.7 XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_pivot_detect.nasl");
  script_mandatory_keys("Pivot/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35363");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35363");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8941");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass
  security restrictions by gaining sensitive information, execute arbitrary
  html or webscript code and redirect the user to other malicious sites.");

  script_tag(name:"affected", value:"Pivot version 1.40.7 and prior.");

  script_tag(name:"insight", value:"- The input passed into several parameters in the pivot/index.php and
  pivot/user.php is not sanitised before being processed.

  - An error in pivot/tb.php while processing invalid url parameter reveals
  sensitive information such as the installation path in an error message.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Pivot is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit(0);

if( version_is_less_equal( version:vers, test_version:"1.40.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
