# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:netscaler";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105468");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-16 11:03:39 +0100 (Mon, 16 Nov 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2015-7996", "CVE-2015-7997", "CVE-2015-7998");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix NetScaler Service Delivery Appliance Multiple Security Updates (CTX202482)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_citrix_netscaler_consolidation.nasl");
  script_mandatory_keys("citrix/netscaler/detected");

  script_tag(name:"summary", value:"Citrix NetScaler is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2015-7996: Vulnerability in Citrix NetScaler Service Delivery Appliance Service VM (SVM)
  Nitro API could result in browser cache cleartext credential theft.

  - CVE-2015-7997: Cross-Site Scripting vulnerabilities in Citrix NetScaler Service Delivery
  Appliance Service VM (SVM) User Interface Nitro API.

  - CVE-2015-7998: Vulnerability in Citrix NetScaler Service Delivery Appliance Service VM (SVM)
  administration UI could result in local information disclosure.");

  script_tag(name:"affected", value:"Citrix NetScaler version 10.5 and 10.5e up to and including
  10.5 Build 57.7 and 10.5 Build 54.9009.e, version 10.1, 10.1e and earlier up to and including
  10.1 Build 132.8.");

  script_tag(name:"solution", value:"Update to version 10.5 Build 58.11, 10.5.e Build 56.1505.e and
  10.1 Build 133.9 or later.");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX202482");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork: TRUE ) )
  exit( 0 );

if( get_kb_item( "citrix/netscaler/enhanced_build" ) )
  enhanced = TRUE;

if( enhanced ) {
  if( version_in_range( version:vers, test_version:"10.5", test_version2:"10.5.55.8006" ) ) {
    fix = "10.5.e Build 55.8007.e";
    vers = vers + ".e";
  }
}
else {
  if( version_in_range( version:vers, test_version:"10.5", test_version2:"10.5.55.6" ) )
    fix = "10.5 Build 55.7";

  if( version_in_range( version:vers, test_version:"10.1", test_version2:"10.1.131.6" ) )
    fix = "10.1 Build 131.7";
}

if( fix ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
