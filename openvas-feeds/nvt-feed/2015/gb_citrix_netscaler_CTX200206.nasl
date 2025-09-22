# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:netscaler";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105273");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-12 13:11:00 +0200 (Tue, 12 May 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-7140");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix NetScaler RCE Vulnerability (CTX200206)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_citrix_netscaler_consolidation.nasl");
  script_mandatory_keys("citrix/netscaler/detected");

  script_tag(name:"summary", value:"Citrix NetScaler is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An unauthenticated attacker could execute arbitrary code on the
  appliance.");

  script_tag(name:"affected", value:"Citrix NetScaler prior to version 10.5-50.10 / 10.1-129.11");

  script_tag(name:"solution", value:"Update to version 10.5-50.10 / 10.1-129.11 or later.");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX200206");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70696");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( get_kb_item( "citrix/netscaler/enhanced_build" ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, nofork: TRUE) )
  exit( 0 );

if( vers =~ "^10\.1\." ) {
  if( version_is_less( version: vers, test_version: "10.1.129.11" ) )
    fix = "10.1 build 129.11";
}
else if (vers =~ "^10\.5\." || vers =~ "^10\.0\.") {
  if( version_is_less( version: vers, test_version: "10.5.50.10" ) )
    fix = "10.5 build 50.10";
}

if( fix ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
