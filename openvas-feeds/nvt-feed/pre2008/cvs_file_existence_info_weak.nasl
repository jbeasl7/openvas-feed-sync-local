# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cvs:cvs";

# Ref: Sebastian Krahmer

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14313");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10955");
  script_cve_id("CVE-2004-0778");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("CVS file existence information disclosure weakness");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("General");
  script_dependencies("cvspserver_version.nasl");
  script_mandatory_keys("cvspserver/detected");

  script_tag(name:"solution", value:"Upgrade to CVS 1.11.17 and 1.12.9, or newer.");

  script_tag(name:"summary", value:"The remote CVS server, according to its version number,
  can be exploited by malicious users to gain knowledge of certain system information.");

  script_tag(name:"impact", value:"This behaviour can be exploited to determine the existence
  and permissions of arbitrary files and directories on a vulnerable system.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.11.17" ) ||
    version_in_range( version:vers, test_version:"1.12", test_version2:"1.12.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.11.17/1.12.9" );
  security_message( port:port, data:report );
}

exit( 0 );