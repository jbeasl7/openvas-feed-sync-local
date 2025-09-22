# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpgroupware:phpgroupware";

# Ref: PhpGroupWare Team

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14293");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10895");
  script_xref(name:"OSVDB", value:"8354");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("PhpGroupWare plaintext cookie authentication credentials vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("phpgroupware_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpGroupWare/installed");


  script_tag(name:"solution", value:"Update to version 0.9.16.002 or newer");
  script_tag(name:"summary", value:"The remote host seems to be running PhpGroupWare.

  PhpGroupWare is a multi-user groupware suite written in PHP.");
  script_tag(name:"insight", value:"This version is reported to contain a plaintext cookie authentication
  credentials information disclosure vulnerability. If the web
  administration of PHPGroupWare is not conducted over an encrypted link,
  an attacker with the ability to sniff network traffic could easily
  retrieve these passwords. This may aid the attacker in further system
  compromise.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( ereg( pattern:"^0\.([0-8]\.|9\.([0-9]\.|1[0-5]\.|16\.0*[01]([^0-9]|$)))", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.9.16.002" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );