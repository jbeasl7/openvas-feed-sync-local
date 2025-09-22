# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800471");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4274");
  script_name("NetPBM 'xpmtoppm' Converter Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_netpbm_detect.nasl");
  script_family("Buffer overflow");
  script_mandatory_keys("NetPBM/Ver");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=546580");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38164");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to crash an affected application or
  execute arbitrary code by tricking a user into converting a malicious image.");

  script_tag(name:"affected", value:"NetPBM versions prior to 10.47.07.");

  script_tag(name:"insight", value:"The flaw is due a buffer overflow error in the 'converter/ppm/xpmtoppm.c'
  converter when processing malformed header fields of 'X PixMap' (XPM) image files.");

  script_tag(name:"summary", value:"NetPBM is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution", value:"Apply the patch or update to NetPBM 10.47.07.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:netpbm:netpbm";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

# NetPBM version 10.47.07(10.47.7)
if( version_is_less( version: version, test_version: "10.47.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "10.47.7", install_path: location );
  security_message(port: 0, data: report);
  exit( 0 );
}

exit( 99 );
