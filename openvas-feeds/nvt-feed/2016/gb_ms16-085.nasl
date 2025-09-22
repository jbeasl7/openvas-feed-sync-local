# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807346");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-3244", "CVE-2016-3246", "CVE-2016-3248", "CVE-2016-3259",
                "CVE-2016-3260", "CVE-2016-3264", "CVE-2016-3265", "CVE-2016-3269",
                "CVE-2016-3271", "CVE-2016-3273", "CVE-2016-3274", "CVE-2016-3276",
                "CVE-2016-3277");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:12:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-07-13 08:14:54 +0530 (Wed, 13 Jul 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Edge Multiple Vulnerabilities (3169999)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-085.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A security feature bypass exists when Microsoft Edge does not properly
    implement Address Space Layout Randomization (ASLR).

  - Multiple remote code execution vulnerabilities exist when Microsoft Edge
    improperly accesses objects in memory.

  - Multiple remote code execution vulnerabilities exist in the way that the
    Chakra JavaScript engine renders when handling objects in memory

  - A spoofing vulnerability exists when a Microsoft browser does not properly
    parse HTTP content.

  - A spoofing vulnerability exists when the Microsoft Browser in reader mode
    does not properly parse HTML content.

  - An information disclosure vulnerability exists when the Microsoft Browser
    improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to trick a user into loading a page containing malicious content,
  to trick the user into opening the .pdf file and read information in the context
  of the current user and to execute arbitrary code.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3163912");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91599");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91602");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91581");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91580");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91598");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91573");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91595");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91586");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91576");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91591");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91593");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91596");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3172985");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-085");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Edge/Installed");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgedllVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgedllVer){
  exit(0);
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:edgedllVer, test_version:"11.0.10240.17024"))
  {
    Vulnerable_range = "Less than 11.0.10240.17024";
    VULN = TRUE ;
  }

  else if(version_in_range(version:edgedllVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.493"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.493";
    VULN = TRUE ;
  }
}


if(VULN)
{
  report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
           'File version:     ' + edgedllVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

exit(0);
