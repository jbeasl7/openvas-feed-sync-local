# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105588");
  script_cve_id("CVE-2016-1299");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco Small Business SG300 Managed Switch Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82103");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160127-sbms");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw87174");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause denial-of-service conditions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling, processing, and termination of HTTPS connections.
  An attacker could exploit this vulnerability by sending crafted HTTPS requests to management-enabled interfaces of an affected system.");

  script_tag(name:"solution", value:"Update to version 1.4.5.2 or later. Please see the references for more information.");

  script_tag(name:"summary", value:"Cisco Small Business SG300 Managed Switch is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"affected", value:"Cisco Small Business SG300 Managed Switch Release 1.4.1.x is vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-18 21:58:00 +0000 (Thu, 18 Feb 2016)");
  script_tag(name:"creation_date", value:"2016-03-24 15:41:40 +0100 (Thu, 24 Mar 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_small_business_switch_consolidation.nasl");
  script_mandatory_keys("cisco/sb_switch/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:cisco:sf300-08_firmware",
                     "cpe:/o:cisco:sf300-24_firmware",
                     "cpe:/o:cisco:sf300-24mp_firmware",
                     "cpe:/o:cisco:sf300-24p_firmware",
                     "cpe:/o:cisco:sf300-24pp_firmware",
                     "cpe:/o:cisco:sf300-48_firmware",
                     "cpe:/o:cisco:sf300-48p_firmware",
                     "cpe:/o:cisco:sf300-48pp_firmware",
                     "cpe:/o:cisco:sf302-08_firmware",
                     "cpe:/o:cisco:sf302-08mp_firmware",
                     "cpe:/o:cisco:sf302-08mpp_firmware",
                     "cpe:/o:cisco:sf302-08p_firmware",
                     "cpe:/o:cisco:sf302-08pp_firmware",
                     "cpe:/o:cisco:sg300-10_firmware",
                     "cpe:/o:cisco:sg300-10mp_firmware",
                     "cpe:/o:cisco:sg300-10mpp_firmware",
                     "cpe:/o:cisco:sg300-10p_firmware",
                     "cpe:/o:cisco:sg300-10pp_firmware",
                     "cpe:/o:cisco:sg300-10sfp_firmware",
                     "cpe:/o:cisco:sg300-20_firmware",
                     "cpe:/o:cisco:sg300-28_firmware",
                     "cpe:/o:cisco:sg300-28mp_firmware",
                     "cpe:/o:cisco:sg300-28p_firmware",
                     "cpe:/o:cisco:sg300-28pp_firmware",
                     "cpe:/o:cisco:sg300-52_firmware",
                     "cpe:/o:cisco:sg300-52mp_firmware",
                     "cpe:/o:cisco:sg300-52p_firmware");

if( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork: TRUE ) )
  exit( 0 );

version = infos["version"];

if( version_in_range( version:version, test_version:"1.4.1", test_version2:"1.4.1.03" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"Ask the vendor" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
