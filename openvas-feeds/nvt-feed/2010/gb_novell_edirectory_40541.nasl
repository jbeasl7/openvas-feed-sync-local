# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netiq:edirectory";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100667");
  script_version("2024-09-16T09:36:54+0000");
  script_tag(name:"last_modification", value:"2024-09-16 09:36:54 +0000 (Mon, 16 Sep 2024)");
  script_tag(name:"creation_date", value:"2010-06-04 13:05:19 +0200 (Fri, 04 Jun 2010)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2009-4653");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Novell eDirectory Multiple Vulnerabilities (Jun 2010)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_netiq_edirectory_ldap_detect.nasl");
  script_mandatory_keys("netiq/edirectory/detected");

  script_tag(name:"summary", value:"Novell eDirectory is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploits may allow attackers to execute arbitrary
  code within the context of the affected application or cause denial of service conditions.");

  script_tag(name:"affected", value:"Novell eDirectory versions prior to 8.8 SP5 Patch 4.");

  script_tag(name:"solution", value:"Update to version 8.8 SP5 Patch 4 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40541");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=3426981");
  script_xref(name:"URL", value:"http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5076150.html");
  script_xref(name:"URL", value:"http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5076151.html");

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

reportver = major;

if( sp > 0 )
  reportver += " SP" + sp;

revision = get_kb_item( "netiq/edirectory/" + port + "/build" );
revision = str_replace( string:revision, find:".", replace:"" );

if(  major == "8.8" ) {
  if( sp && sp > 0 ) {
    if( sp == 5 ) {
      if( revision && int( revision ) < 2050413 ) { # < eDirectory 8.8 SP5 Patch 4 (20504.13)
        vuln = TRUE;
      }
    } else {
      if( sp < 5 ) {
        vuln = TRUE;
      }
    }
  } else {
    vuln = TRUE;
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:reportver, fixed_version:"See advisory" );
  security_message( port:port, data:report );
  exit(0);
}

exit( 99 );
