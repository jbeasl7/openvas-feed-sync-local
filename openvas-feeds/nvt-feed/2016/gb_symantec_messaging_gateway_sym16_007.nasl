# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:messaging_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105722");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-05-17 13:54:13 +0200 (Tue, 17 May 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:29:00 +0000 (Thu, 15 Oct 2020)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0160");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symantec Messaging Gateway 10.6.x ACE Library Static Link to Vulnerable SSL Version (SYM16-007)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_messaging_gateway_consolidation.nasl");
  script_mandatory_keys("symantec/smg/detected");

  script_tag(name:"summary", value:"Symantec Messaging Gateway (SMG) Appliance management console
  is susceptible to potential unauthorized loss of privileged information due to an inadvertent
  static link of an updated component library to a version of SSL susceptible to the Heartbleed
  vulnerability (CVE-2014-0160).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Symantec became aware of a recently updated ACE library shipped
  in SMG 10.6.x that was statically linked inadvertently to a version of SSL susceptible to
  CVE-2014-0160, Heartbleed vice dynamically linked to the non-vulnerable SSL version in the
  shipping OS of the Appliance.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway version 10.x, 10.6.1 and prior.");

  script_tag(name:"solution", value:"Update to version 10.6.1-3 or later.");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2016&suid=20160512_00");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66690");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"10.6.1" ) )
  vuln = TRUE;

patch = get_kb_item( "symantec/smg/patch" );

if( version == "10.6.1" ) {
  if( patch ) {
    if( int( patch ) < 3 )
      vuln = TRUE;
  } else
    vuln = TRUE;
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, installed_patch:patch,
                             fixed_version:"10.6.1", fixed_patch:"3" );
  security_message( port:0, data:report );
  exit(0);
}

exit( 99 );
