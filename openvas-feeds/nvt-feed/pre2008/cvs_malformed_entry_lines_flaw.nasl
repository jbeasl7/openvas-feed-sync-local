# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cvs:cvs";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12265");
  script_version("2024-08-02T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-08-02 05:05:39 +0000 (Fri, 02 Aug 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10499");
  script_cve_id("CVE-2004-0414", "CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418",
                "CVE-2004-1471");
  script_xref(name:"RHSA", value:"RHSA-2004:233-017");
  script_name("CVS < 1.11.17, 1.12.x < 1.12.9 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("General");
  script_dependencies("cvspserver_version.nasl");
  script_mandatory_keys("cvspserver/detected");

  script_tag(name:"summary", value:"CVS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2004-0414: a vulnerability related to the handling of malformed 'Entry' lines

  - CVE-2004-0416: a double-free relating to the error_prog_name string

  - CVE-2004-0417: an argument integer overflow

  - CVE-2004-0418: out-of-bounds writes in serv_notify

  - CVE-2004-1471: format string vulnerability in wrapper.c");

  script_tag(name:"affected", value:"CVS versions prior to 1.11.17 and 1.12.x prior to 1.12.9.");

  script_tag(name:"solution", value:"Update to version 1.11.17, 1.12.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.11.17" ) ||
    version_in_range( version:vers, test_version:"1.12", test_version2:"1.12.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.11.17/1.12.9" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
