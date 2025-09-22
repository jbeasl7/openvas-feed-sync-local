# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:netscaler";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105309");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-01 13:34:32 +0200 (Wed, 01 Jul 2015)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2015-5080");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix NetScaler Arbitrary Command Injection (CTX201149)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_citrix_netscaler_consolidation.nasl");
  script_mandatory_keys("citrix/netscaler/detected");

  script_tag(name:"summary", value:"Citrix NetScaler is prone to a command injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been identified in Citrix NetScaler
  Application Delivery Controller (ADC) and Citrix NetScaler Gateway Management Interface that
  could allow an authenticated malicious user to execute shell commands on the appliance.");

  script_tag(name:"affected", value:"Citrix NetScaler version 10.5 prior to 10.5 Build 56.15,
  10.5.e prior to Build 56.1505.e and 10.1 prior to 10.1.132.8.");

  script_tag(name:"solution", value:"Update to version 10.5 Build 56.15, 10.1 Build 132.8,
  10.5.e Build 56.1505.e or later.");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX201149");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork: TRUE ) )
  exit( 0 );

if( get_kb_item( "citrix/netscaler/enhanced_build" ) )
  enhanced = TRUE;

if( enhanced ) {
  if( version_in_range( version:vers, test_version:"10.5", test_version2:"10.5.56.1504" ) ) {
    fix = "10.5 build 56.1504.e";
    vers = vers + ".e";
  }
}
else {
  if( version_in_range( version:vers, test_version:"10.5", test_version2:"10.5.56.14" ) ) {
    fix = "10.5 build 56.15";
  }

  if( version_in_range( version:vers, test_version:"10.1", test_version2:"10.1.132.7" ) ) {
    fix = "10.1 build 132.8";
  }
}

if( fix ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
