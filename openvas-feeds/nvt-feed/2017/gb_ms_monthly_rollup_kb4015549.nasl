# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810851");
  script_version("2024-07-04T05:05:37+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-6629", "CVE-2017-0058", "CVE-2017-0155", "CVE-2017-0156",
                "CVE-2017-0158", "CVE-2017-0163", "CVE-2017-0166", "CVE-2017-0168",
                "CVE-2017-0180", "CVE-2017-0182", "CVE-2017-0183", "CVE-2017-0184",
                "CVE-2017-0191", "CVE-2017-0192", "CVE-2017-0199", "CVE-2017-0202",
                "CVE-2017-0210");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 13:01:17 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-04-12 12:43:38 +0530 (Wed, 12 Apr 2017)");
  script_name("Microsoft Windows Monthly Rollup (KB4015549)");

  script_tag(name:"summary", value:"This host is missing a monthly rollup according
  to Microsoft security update KB4015549.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This security update includes improvements and
  resolves the following security vulnerabilities in Windows: scripting engine,
  Hyper-V, libjpeg image-processing library, Adobe Type Manager Font Driver, Win32K,
  Microsoft Outlook, Internet Explorer, Graphics Component, Windows kernel-mode
  drivers and Lightweight Directory Access Protocol.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute code or elevate user privileges, take control of the affected system,
  and access information from one domain and inject it into another domain.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4015549");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63676");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97462");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97471");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97507");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97455");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97465");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97446");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97418");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97444");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97427");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97428");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97435");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97466");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97452");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97498");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97441");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97512");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(hotfix_check_sp( win7:2, win7x64:2, win2008r2:2 ) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

gdiVer = fetch_file_version(sysPath:sysPath, file_name:"Ole32.dll");
if(!gdiVer){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:gdiVer, test_version:"6.1.7601.23714"))
  {
    report = 'File checked:     ' + sysPath + "\Ole32.dll" + '\n' +
             'File version:     ' + gdiVer  + '\n' +
             'Vulnerable range:  Less than 6.1.7601.23714\n' ;
    security_message(data:report);
    exit(0);
  }
}
exit(0);
