# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netiq:edirectory";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805269");
  script_version("2024-09-16T09:36:54+0000");
  script_tag(name:"last_modification", value:"2024-09-16 09:36:54 +0000 (Mon, 16 Sep 2024)");
  script_tag(name:"creation_date", value:"2015-02-06 12:01:38 +0530 (Fri, 06 Feb 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-5212", "CVE-2014-5213");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Novell eDirectory iMonitor Multiple Vulnerabilities (Feb 2015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_netiq_edirectory_ldap_detect.nasl");
  script_mandatory_keys("netiq/edirectory/detected");

  script_tag(name:"summary", value:"Novell eDirectory is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Improper sanitization by the /nds/search/data script when input is passed via the 'rdn'
  parameter.

  - An error in the /nds/files/opt/novell/eDirectory/lib64/ndsimon/public/images.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary script code in a user's browser session within the trust relationship between their
  browser and the server, and disclose virtual memory including passwords.");

  script_tag(name:"affected", value:"Novell eDirectory prior to version 8.8 SP8 Patch 4.");

  script_tag(name:"solution", value:"Update to version 8.8 SP8 Patch 4 or later.");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031408");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71741");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71748");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/534284");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=3426981");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! major = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( ! sp = get_kb_item( "netiq/edirectory/" + port + "/sp" ) )
  sp = "0";

instvers = major;

if( sp > 0 )
  instvers += " SP" + sp;

revision = get_kb_item( "netiq/edirectory/" + port + "/build" );
revision = str_replace( string:revision, find:".", replace:"" );

if( major <= "8.8" && sp <= "8" && revision <= "2080404" ) {
  report = report_fixed_ver( installed_version:instvers, fixed_version:"8.8 SP8 Patch4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
