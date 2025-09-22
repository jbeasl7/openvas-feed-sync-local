# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xoops:xoops";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801932");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("XOOPS 'imagemanager.php' Local File Inclusion Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://dl.packetstormsecurity.net/1104-exploits/xoops250-lfi.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47418");
  script_xref(name:"URL", value:"http://www.allinfosec.com/2011/04/18/webapps-0day-xoops-2-5-0-imagemanager-php-lfi-vulnerability-2/");

  script_tag(name:"summary", value:"XOOPS is prone to local file inclusion vulnerability.");
  script_tag(name:"insight", value:"The flaw is due to input validation error in 'target' parameter
  to 'imagemanager.php', which allows attackers to read arbitrary files via a
  ../(dot dot) sequences.");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform file
  inclusion attacks and read arbitrary files on the affected application.");
  script_tag(name:"affected", value:"XOOPS version 2.5.0 and prior.");
  script_tag(name:"solution", value:"Upgrade to version 2.5.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/xoops");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2.5.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.5.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
