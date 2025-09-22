# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:znc:znc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100758");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-13 12:44:16 +0200 (Fri, 13 Aug 2010)");
  script_cve_id("CVE-2010-2812", "CVE-2010-2934");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("ZNC < 0.094 Multiple DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_znc_consolidation.nasl");
  script_mandatory_keys("znc/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42314");
  script_xref(name:"URL", value:"http://znc.svn.sourceforge.net/viewvc/znc?view=revision&revision=2093");
  script_xref(name:"URL", value:"http://znc.svn.sourceforge.net/viewvc/znc?view=revision&revision=2095");

  script_tag(name:"summary", value:"ZNC is prone to multiple remote denial-of-service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may exploit these issues to crash the application,
  resulting in denial-of-service conditions.");

  script_tag(name:"affected", value:"ZNC 0.092 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"0.092" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.094" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
