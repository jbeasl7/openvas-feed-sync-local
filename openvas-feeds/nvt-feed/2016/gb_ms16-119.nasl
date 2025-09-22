# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809439");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-3267", "CVE-2016-3331", "CVE-2016-3382", "CVE-2016-3386",
                "CVE-2016-3387", "CVE-2016-3388", "CVE-2016-3389", "CVE-2016-3390",
                "CVE-2016-3391", "CVE-2016-3392", "CVE-2016-7189", "CVE-2016-7190",
                "CVE-2016-7194");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:12:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-10-12 08:03:50 +0530 (Wed, 12 Oct 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Edge Multiple Vulnerabilities (3192890)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-119.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A remote code execution exist in the way that the Chakra JavaScript engine
    renders when handling objects in memory.

  - A remote code execution vulnerability exists in the way that Microsoft
    Edge improperly handles objects in memory.

  - An information disclosure exists when Microsoft browsers leave credential
    data in memory.

  - Multiple information disclosure exists when the Microsoft Edge improperly
    handles objects in memory.

  - An elevation of privilege when Microsoft Edge fails to properly secure
    private namespace.

  - A security feature bypass flaw exists when the Edge Content Security Policy
    fails to properly handle validation of certain specially crafted documents.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the current user, and
  obtain information to further compromise the users system.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows 10 Version 1607 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3192890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93387");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93386");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93426");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93381");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93382");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93398");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93383");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93379");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93401");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93427");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93399");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-119");

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
  if(version_is_less(version:edgedllVer, test_version:"11.0.10240.17146"))
  {
    Vulnerable_range = "Less than 11.0.10240.17146";
    VULN = TRUE ;
  }

  else if(version_in_range(version:edgedllVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.632"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.632";
    VULN = TRUE ;
  }

  else if(version_in_range(version:edgedllVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.320"))
  {
    Vulnerable_range = "11.0.14393.0 - 11.0.14393.320";
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
