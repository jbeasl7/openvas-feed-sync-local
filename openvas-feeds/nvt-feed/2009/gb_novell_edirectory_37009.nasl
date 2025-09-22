# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netiq:edirectory";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100343");
  script_version("2024-09-16T09:36:54+0000");
  script_tag(name:"last_modification", value:"2024-09-16 09:36:54 +0000 (Mon, 16 Sep 2024)");
  script_tag(name:"creation_date", value:"2009-11-13 12:21:24 +0100 (Fri, 13 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2009-4653");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Novell eDirectory <= 8.8 SP5 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_netiq_edirectory_ldap_detect.nasl");
  script_mandatory_keys("netiq/edirectory/detected");

  script_tag(name:"summary", value:"Novell eDirectory is prone to a buffer-overflow vulnerability
  because it fails to perform adequate boundary checks on user-supplied data.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code in
  the context of the affected application. Failed exploit attempts will likely cause denial of
  service conditions.");

  script_tag(name:"affected", value:"Novell eDirectory version 8.8 SP5 and probably prior.");

  script_tag(name:"solution", value:"See the references for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37009");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507812");

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

revision = get_kb_item( "netiq/edirectory/" + port + "/build" );

instver = major;

if( sp > 0 )
  instver += " SP" + sp;

if( major == "8.8" ) {
  if( sp && sp > 0 ) {
    if( sp == 5 ) {
      if( ! revision ) {
        VULN = TRUE;
      }
    }

    if( sp < 5 ) {
      VULN = TRUE;
    }
  } else {
    VULN = TRUE;
  }
} else if( major == "8.8.1" ) {
  VULN = TRUE;
} else if( major == "8.8.2" ) {
  if( ! revision && ! sp ) {
    VULN = TRUE;
  }
}

if( VULN ) {
  report = report_fixed_ver( installed_version:instver, fixed_version:"See advisory" );
  security_message( port:port, data:report );
  exit(0);
}

exit(99);
