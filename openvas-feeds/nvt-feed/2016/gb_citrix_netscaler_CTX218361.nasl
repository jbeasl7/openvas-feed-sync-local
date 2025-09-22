# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:netscaler";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140036");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-10-28 12:53:02 +0200 (Fri, 28 Oct 2016)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)");

  script_cve_id("CVE-2016-9028");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix NetScaler ADC Unauthorized Redirect Vulnerability (CTX218361)");

  script_tag(name:"summary", value:"An unauthorized redirect vulnerability has been identified in
  Citrix NetScaler ADC that could allow a remote attacker to obtain session cookies of a redirected
  AAA user.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_citrix_netscaler_consolidation.nasl");
  script_mandatory_keys("citrix/netscaler/detected");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Citrix NetScaler ADC version 11.1 earlier than
  11.1 Build 47.14, 11.0 earlier than 11.0 Build 65.31/65.35F, 10.5 earlier than 10.5 Build 61.11
  and 10.1 earlier than 10.1 Build 135.8.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX218361");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork: TRUE ) )
  exit( 0 );

if( get_kb_item( "citrix/netscaler/enhanced_build" ) )
  enhanced = TRUE;

if( enhanced )
  exit( 99 );

if( version_in_range( version:vers, test_version:"10.5", test_version2:"10.5.61.10" ) )
  fix = "10.5 Build 61.11";

if( version_in_range( version:vers, test_version:"10.1", test_version2:"10.1.135.7" ) )
  fix = "10.1 build 135.8";

if( version_in_range( version:vers, test_version:"11.0", test_version2:"11.0.65.30" ) )
  fix = "11.0 Build 65.31";

if( version_in_range( version:vers, test_version:"11.1", test_version2:"11.1.47.13" ) )
  fix = "11.1 Build 47.14";

if( fix ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
