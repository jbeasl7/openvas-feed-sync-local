# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:onenote";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836205");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2025-29822");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-08 18:16:08 +0000 (Tue, 08 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-09 12:14:07 +0530 (Wed, 09 Apr 2025)");
  script_name("Microsoft OneNote Security Feature Bypass Vulnerability (KB5002622)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002622.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a security feature bypass
  vulnerability in Microsoft Office.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct security feature bypass.");

  script_tag(name:"affected", value:"Microsoft OneNote 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002622");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_onenote_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/OneNote/Ver");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );

notePath = infos["location"];
if( ! notePath || "Could not find the install location" >< notePath ) {
  exit( 0 );
}

noteVer = fetch_file_version(sysPath:notePath, file_name:"onmain.dll");
if(noteVer && noteVer =~ "^16") {
  Vulnerable_range  =  "16.0 - 16.0.5495.1000";

  if(version_in_range(version:noteVer, test_version:"16.0", test_version2:"16.0.5495.1000")) {
    report = report_fixed_ver(file_checked:notePath + "\onmain.dll",
                 file_version:noteVer, vulnerable_range:Vulnerable_range );
        security_message(port:0, data:report);
    exit(0);
  }
}

exit( 99 );
