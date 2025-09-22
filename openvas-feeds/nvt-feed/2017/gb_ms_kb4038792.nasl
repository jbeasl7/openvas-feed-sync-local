# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811665");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-8675", "CVE-2017-8676", "CVE-2017-8737", "CVE-2017-8741",
                "CVE-2017-0161", "CVE-2017-8720", "CVE-2017-8728", "CVE-2017-8628",
                "CVE-2017-8733", "CVE-2017-8736", "CVE-2017-8677", "CVE-2017-8678",
                "CVE-2017-8747", "CVE-2017-8748", "CVE-2017-8749", "CVE-2017-8679",
                "CVE-2017-8680", "CVE-2017-8681", "CVE-2017-8750", "CVE-2017-8682",
                "CVE-2017-8683", "CVE-2017-8684", "CVE-2017-8686", "CVE-2017-8687",
                "CVE-2017-8688", "CVE-2017-8692", "CVE-2017-8695", "CVE-2017-8699",
                "CVE-2017-8707", "CVE-2017-8708", "CVE-2017-8709", "CVE-2017-8713",
                "CVE-2017-8714", "CVE-2017-8719");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-21 18:17:00 +0000 (Thu, 21 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-09-13 09:14:23 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4038792)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4038792");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This security update includes improvements and
  fixes that resolves,

  - Internet Explorer 11's navigation bar with search box.

  - Internet Explorer where undo is broken if character conversion is canceled
    using IME.

  - Internet Explorer where graphics render incorrectly.

  - Internet Explorer where the Delete key functioned improperly.

  - NPS server where EAP TLS authentication was broken.

  - Security updates to Microsoft Graphics Component, Windows kernel-mode drivers,
    Windows shell, Microsoft Uniscribe, Microsoft Windows PDF Library, Windows TPM,
    Windows Hyper-V, Windows kernel, Windows DHCP Server, and Internet Explorer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to get information on the Hyper-V host operating system, could
  retrieve the base address of the kernel driver from a compromised process, could
  obtain information to further compromise the users system.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4038792");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100752");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100749");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100764");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100728");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100739");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100744");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100737");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100743");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100767");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100769");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100766");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100770");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100720");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100727");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100771");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100772");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100781");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100782");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100730");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100736");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100756");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100762");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100773");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100783");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100790");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100791");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100792");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100796");
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

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"drivers\vpcivsp.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.3.9600.18790"))
{
  report = 'File checked:     ' + sysPath + "drivers\vpcivsp.sys" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range:  Less than 6.3.9600.18790\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
