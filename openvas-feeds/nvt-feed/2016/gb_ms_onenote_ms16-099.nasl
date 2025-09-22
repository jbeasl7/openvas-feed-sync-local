# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:onenote";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807871");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2016-3315");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:12:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-08-10 10:27:21 +0530 (Wed, 10 Aug 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft OneNote Information Disclosure Vulnerability (3177451)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-099.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist as Microsoft OneNote improperly
  discloses its memory contents.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"- Microsoft OneNote 2007 Service Pack 3

  - Microsoft OneNote 2010 Service Pack 2

  - Microsoft OneNote 2013 Service Pack 1

  - Microsoft OneNote 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114456");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92294");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114885");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115256");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115419");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-099");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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
if(noteVer) {
  if(noteVer =~ "^(12|14|15|16).*") {
    if(noteVer =~ "^12"){
      Vulnerable_range  =  "12 - 12.0.6753.4999";
    }
    else if(noteVer =~ "^14"){
      Vulnerable_range  =  "14 - 14.0.7172.4999";
    }
    else if(noteVer =~ "^15"){
      Vulnerable_range  =  "15 - 15.0.4849.0999";
    }
    else if(noteVer =~ "^16"){
      Vulnerable_range  =  "16 - 16.0.4417.0999";
    }
  }
  if(version_in_range(version:noteVer, test_version:"12.0", test_version2:"12.0.6753.4999") ||
     version_in_range(version:noteVer, test_version:"14.0", test_version2:"14.0.7172.4999") ||
     version_in_range(version:noteVer, test_version:"15.0", test_version2:"15.0.4849.0999") ||
     version_in_range(version:noteVer, test_version:"16.0", test_version2:"16.0.4417.0999")) {
    report = 'File checked:     ' + notePath + "\onmain.dll"  + '\n' +
             'File version:     ' + noteVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

exit( 99 );
