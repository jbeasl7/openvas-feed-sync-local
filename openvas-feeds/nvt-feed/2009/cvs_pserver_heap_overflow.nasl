# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cvs:cvs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100289");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-10-05 19:43:01 +0200 (Mon, 05 Oct 2009)");
  script_cve_id("CVE-2004-0396");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CVS Malformed Entry Modified and Unchanged Flag Insertion Heap Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("cvspserver_version.nasl");
  script_mandatory_keys("cvspserver/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10384");
  script_xref(name:"URL", value:"http://security.e-matters.de/advisories/072004.html?SID=384b888de96e3bce19306db8577fca26");
  script_xref(name:"URL", value:"http://support.coresecurity.com/impact/exploits/62024ecea12fe1bbd01479065b3a1797.html");
  script_xref(name:"URL", value:"http://ccvs.cvshome.org/");
  script_xref(name:"URL", value:"https://marc.info/?l=openbsd-security-announce&m=108508894405639&w=2");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2004-190.html");
  script_xref(name:"URL", value:"http://www.us-cert.gov/cas/techalerts/TA04-147A.html");

  script_tag(name:"summary", value:"CVS is prone to a remote heap overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This issue presents itself during the handling of user-supplied
  input for entry lines with 'modified' and 'unchanged' flags.");

  script_tag(name:"impact", value:"This vulnerability can allow an attacker to overflow a vulnerable
  buffer on the heap, possibly leading to arbitrary code execution.");

  script_tag(name:"affected", value:"CVS versions 1.11.15 and prior and CVS feature versions 1.12.7 and
  prior are prone to this issue.");

  script_tag(name:"solution", value:"CVS versions 1.11.16 and 1.12.8 have been released to address
  this issue.");

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

if( version_is_less( version:vers, test_version:"1.11.16" ) ||
    version_in_range( version:vers, test_version:"1.12", test_version2:"1.12.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.11.16/1.12.8" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
