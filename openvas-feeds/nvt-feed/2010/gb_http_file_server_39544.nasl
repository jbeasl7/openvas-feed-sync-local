# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:httpfilesever:hfs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100585");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-04-19 20:46:01 +0200 (Mon, 19 Apr 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("HTTP File Server Security Bypass and Denial of Service Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39544");
  script_xref(name:"URL", value:"http://www.rejetto.com/hfs/?f=intro");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/hfsref-adv.txt");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_http_file_server_detect.nasl");
  script_mandatory_keys("hfs/Installed");

  script_tag(name:"affected", value:"HttpFileServer version 2.2e and prior.");

  script_tag(name:"solution", value:"Update to version 2.2f or later.");

  script_tag(name:"summary", value:"HTTP File Server is prone to multiple vulnerabilities including a security-
  bypass issue and a denial-of-service issue.");

  script_tag(name:"impact", value:"Exploiting these issues will allow an attacker to download files from
  restricted directories within the context of the application or cause denial-of-service conditions.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"2.2f" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2f" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
