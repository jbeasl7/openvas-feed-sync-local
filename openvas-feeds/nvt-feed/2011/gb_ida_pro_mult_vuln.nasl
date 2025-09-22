# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901189");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2011-1049", "CVE-2011-1050", "CVE-2011-1051",
                "CVE-2011-1052", "CVE-2011-1053", "CVE-2011-1054");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Hex-Rays IDA Pro Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_ida_pro_detect.nasl");
  script_mandatory_keys("IDA/Pro/Ver");

  script_xref(name:"URL", value:"https://www.hex-rays.com/vulnfix.shtml");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code or
  cause a denial of service.");

  script_tag(name:"affected", value:"Hex-Rays IDA Pro versions 5.7 and 6.0.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - A buffer overflow error in the Mach-O input file loader allows user-assisted
  remote attackers to cause a denial of service.

  - An unspecified error related to 'conversion of string encodings' and
  'inconsistencies in the handling of UTF8 sequences by the user interface'.

  - An integer overflow error in the COFF/EPOC/EXPLOAD input file loaders.

  - An Integer overflow error in the PSX/GEOS input file loaders.

  - An unspecified error in the Mach-O input file loader allows user-assisted
  remote attackers to cause a denial of service.

  - An unspecified error in the PEF input file loader.");

  script_tag(name:"summary", value:"Hex-Rays IDA Pro is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Apply the patch from the referenced vendor URL or update to the most recent version.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:hex-rays:ida";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version =~ "^6\.0\." || version =~ "^5\.7\." ){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit( 0 );
}

exit( 99 );
