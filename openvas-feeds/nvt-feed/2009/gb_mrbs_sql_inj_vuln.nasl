# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:john_beranek:meeting_room_booking_system";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800950");
  script_version("2024-03-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2009-10-12 07:28:01 +0200 (Mon, 12 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3533");
  script_name("Meeting Room Booking System SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mrbs_detect.nasl");
  script_mandatory_keys("MRBS/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35469");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51772");
  script_xref(name:"URL", value:"http://mrbs.sourceforge.net/view_text.php?section=NEWS&file=NEWS");

  script_tag(name:"impact", value:"Attackers can exploit this issue to inject arbitrary SQL code and modify
  information in the back-end database.");

  script_tag(name:"affected", value:"Meeting Room Booking System prior to 1.4.2 on all platforms.");

  script_tag(name:"insight", value:"The user supplied data passed into 'typematch' parameter in report.php is
  not properly sanitised before being used in an SQL query.");

  script_tag(name:"solution", value:"Upgrade to Meeting Room Booking System 1.4.2 or later.");

  script_tag(name:"summary", value:"Meeting Room Booking System is prone to a SQL Injection vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.4.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
