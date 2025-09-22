# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809091");
  script_version("2024-07-10T05:05:27+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-7195", "CVE-2016-7196", "CVE-2016-7198", "CVE-2016-7199",
                "CVE-2016-7200", "CVE-2016-7201", "CVE-2016-7202", "CVE-2016-7203",
                "CVE-2016-7204", "CVE-2016-7208", "CVE-2016-7209", "CVE-2016-7227",
                "CVE-2016-7239", "CVE-2016-7240", "CVE-2016-7241", "CVE-2016-7242",
                "CVE-2016-7243");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-10 05:05:27 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-09 18:21:10 +0000 (Tue, 09 Jul 2024)");
  script_tag(name:"creation_date", value:"2016-11-09 08:52:24 +0530 (Wed, 09 Nov 2016)");
  script_name("Microsoft Edge Multiple Vulnerabities (3199057)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-129");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The Microsoft Edge improperly handles objects in memory.

  - The Microsoft Edge IMproperly parse HTTP content.

  - The Microsoft browser XSS filter is abused to leak sensitive page information.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary code in the context of the current user, redirect
  a user to a specially crafted website, detect specific files on the user's
  computer, trick a user into allowing access to the user's My Documents folder,
  obtain sensitive information from certain web pages in the affected browser.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3199057");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92828");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92834");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92789");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92830");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92829");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92832");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92807");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92793");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/ms16-129");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

edgePath = smb_get_system32root();
if(!edgePath){
  exit(0);
}

if(!edgeVer = fetch_file_version(sysPath: edgePath, file_name:"edgehtml.dll")){;
  exit(0);
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17184"))
  {
    Vulnerable_range = "Less than 11.0.10240.17184";
    VULN = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.671"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.671";
    VULN = TRUE ;
  }

  else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.446"))
  {
    Vulnerable_range = "11.0.14393.0 - 11.0.14393.446";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + edgePath + "\edgehtml.dll"+ '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
