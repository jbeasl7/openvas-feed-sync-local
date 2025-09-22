# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:netscaler";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140153");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-02-08 12:46:21 +0100 (Wed, 08 Feb 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-14 19:27:00 +0000 (Tue, 14 Mar 2017)");

  script_cve_id("CVE-2017-5933");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix NetScaler Nonce Generation Vulnerability (CTX220329)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_citrix_netscaler_consolidation.nasl");
  script_mandatory_keys("citrix/netscaler/detected");

  script_tag(name:"summary", value:"A flaw has been identified in the GCM nonce generation
  functionality of Citrix NetScaler application Delivery Controller (ADC) and Citrix NetScaler
  Gateway that could result in the interception of session data.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Citrix NetScaler version 11.1 earlier than 11.1 Build 51.21,
  11.0 earlier than 11.0 Build 69.12/69.123 and 10.5 earlier than 10.5 Build 65.11.");

  script_tag(name:"solution", value:"Update to version 11.1 Build 51.21, 11.0 Build 69.12/69.123,
  10.5 Build 65.11 or later");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX220329");
  script_xref(name:"URL", value:"https://github.com/nonce-disrespect/nonce-disrespect");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork: TRUE) )
  exit( 0 );

if( get_kb_item( "citrix/netscaler/enhanced_build" ) )
  enhanced = TRUE;

if( enhanced )
  exit( 99 );

if( version_in_range( version:vers, test_version:"10.5", test_version2:"10.5.65.10" ) )
  fix = "10.5 Build 65.11";

if( version_in_range( version:vers, test_version:"11.0", test_version2:"11.0.69.11" ) )
  fix = "11.0 Build 69.12";

if( version_in_range( version:vers, test_version:"11.1", test_version2:"11.1.51.20" ) )
  fix = "11.1 Build 51.21";

if( fix ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port: 0, data:report );
  exit( 0 );
}

exit( 99 );
