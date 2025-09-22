# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:onedrive";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819961");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2020-0935");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-21 18:42:00 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2022-01-18 11:37:10 +0530 (Tue, 18 Jan 2022)");
  script_name("Microsoft OneDrive Elevation of Privilege Vulnerability (Apr 2020)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Update for month of April.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to OneDrive for Windows Desktop
  application improperly handles symbolic links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run a specially crafted application that could exploit the vulnerability
  and delete a targeted file with an elevated status.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0935");
  script_xref(name:"URL", value:"https://support.office.com/en-us/article/onedrive-release-notes-845dcf18-f921-435e-bf28-4e24b95e5fc0");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_onedrive_detect_win.nasl");
  script_mandatory_keys("microsoft/onedrive/win/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( ! vers || vers =~ "Unknown" )
  exit( 0 );

if( version_is_less( version:vers, test_version:"19.232.1124.0010" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"19.232.1124.0010", install_path:path );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
