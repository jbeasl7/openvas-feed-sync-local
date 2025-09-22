# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:onedrive";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817318");
  script_version("2024-02-19T14:37:31+0000");
  script_cve_id("CVE-2020-1465");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 14:37:31 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-17 17:03:00 +0000 (Fri, 17 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-27 11:50:35 +0530 (Mon, 27 Jul 2020)");
  script_name("Microsoft OneDrive Privilege Escalation Vulnerability (Jul 2020)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Updates for month of July");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in Microsoft
  OneDrive that allows file deletion in arbitrary locations.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain elevated privileges.");

  script_tag(name:"affected", value:"Microsoft OneDrive prior to version 20.114.0607.0002.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1465");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/office/onedrive-release-notes-845dcf18-f921-435e-bf28-4e24b95e5fc0");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_onedrive_detect_win.nasl");
  script_mandatory_keys("microsoft/onedrive/win/detected");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( ! version || version =~ "Unknown" )
  exit( 0 );

if( version_is_less( version:version, test_version:"20.114.0607.0002" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"20.114.0607.0002", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
