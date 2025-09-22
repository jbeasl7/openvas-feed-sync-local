# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:dlink:dir-867_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171552");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-23 14:21:08 +0000 (Mon, 23 Jun 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-20 11:15:22 +0000 (Fri, 20 Jun 2025)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2025-6334");

  script_name("D-Link DIR-867 Buffer Overflow Vulnerability (Jun 2025)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-867 devices are prone to a buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if the target host is a vulnerable device.");

  script_tag(name:"insight", value:"This vulnerability affects the function strncpy of the
  component Query String Handler. The manipulation leads to stack-based buffer overflow.");

  script_tag(name:"affected", value:"D-Link DIR-867 devices in all versions.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Note: Vendor states that DIR-867 devices reached End-of-Support Date in 29.03.2024, they are no
  longer supported, and firmware development has ceased. See vendor advisory for further
  recommendations.");

  script_xref(name:"URL", value:"https://github.com/Thir0th/Thir0th-CVE/blob/main/DIR-867%20AC1750.md");
  script_xref(name:"URL", value:"https://service.dlink.co.in/resources/EOL-Products-Without-Service.pdf");
  script_xref(name:"URL", value:"https://legacy.us.dlink.com/");
  script_xref(name:"URL", value:"https://support.dlink.com/ProductInfo.aspx?m=DIR-867-US");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

report = report_fixed_ver( installed_version:version, fixed_version:"None" );
security_message( port:0, data:report );
exit( 0 );
