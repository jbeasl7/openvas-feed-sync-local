# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107253");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-11-09 14:03:54 +0700 (Thu, 09 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-15 15:43:00 +0000 (Wed, 15 Nov 2017)");

  script_cve_id("CVE-2017-15909");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DGS-1500 Ax RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_dgs_1500_detect.nasl");
  script_mandatory_keys("dgs/1500/detected");

  script_tag(name:"summary", value:"D-Link DGS-1500 Ax devices before 2.51B021 are vulnerable to
  remote code execution (RCE).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to hardcoded password in D-Link DGS-1500 Ax devices before 2.51B021.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain shell access.");

  script_tag(name:"affected", value:"D-Link DGS-1500 Ax devices before 2.51B021");

  script_tag(name:"solution", value:"Update the firmware to version 2.51B021 or higher.");

  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/PRODUCTS/DGS-1500-20/REVA/DGS-1500_REVA_FIRMWARE_PATCH_NOTES_2.51.021_EN.pdf");
  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/PRODUCTS/DGS-1500-28/REVA/DGS-1500_REVA_FIRMWARE_PATCH_NOTES_2.51.021_EN.pdf");
  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/PRODUCTS/DGS-1500-28P/REVA/DGS-1500_REVA_FIRMWARE_PATCH_NOTES_2.51.021_EN.pdf");
  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/PRODUCTS/DGS-1500-52/REVA/DGS-1500_REVA_FIRMWARE_PATCH_NOTES_2.51.021_EN.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:dlink:dgs-1500-20_firmware", "cpe:/o:dlink:dgs-1500-28_firmware", "cpe:/o:dlink:dgs-1500-28p_firmware", "cpe:/o:dlink:dgs-1500-52_firmware");

if( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if( ! firmware = get_app_version( cpe:cpe, port:port ) )
  exit( 0 );

if (version_is_less(version: firmware, test_version: "2.51B021")) {
  report = report_fixed_ver(installed_version: firmware, fixed_version: "2.51B021");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
