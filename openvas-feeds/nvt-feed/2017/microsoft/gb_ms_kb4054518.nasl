# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812245");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-11885", "CVE-2017-11886", "CVE-2017-11887", "CVE-2017-11890",
                "CVE-2017-11894", "CVE-2017-11895", "CVE-2017-11901", "CVE-2017-11903",
                "CVE-2017-11906", "CVE-2017-11907", "CVE-2017-11912", "CVE-2017-11913",
                "CVE-2017-11919", "CVE-2017-11927", "CVE-2017-11930");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-26 15:18:00 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2017-12-13 09:40:51 +0530 (Wed, 13 Dec 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4054518)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4054518");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in RPC if the server has Routing and Remote Access enabled.

  - Internet Explorer improperly accesses objects in memory.

  - Internet Explorer improperly handles objects in memory.

  - Scripting engine handles objects in memory in Microsoft browsers.

  - Windows its:// protocol handler unnecessarily sends traffic to a remote site
    in order to determine the zone of a provided URL.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited this vulnerability to execute code on the target
  system, gain the same user rights as the current user, obtain information to
  further compromise the user's system and could attempt a brute-force attack to
  disclose the password.");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1

  - Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4054518");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102055");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102062");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102063");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102082");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102053");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102054");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102046");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102092");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102091");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102093");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102095");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102058");
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

if(hotfix_check_sp(win2008r2:2, win7:2, win7x64:2) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.23963"))
{
  report = report_fixed_ver( file_checked:sysPath + "\Win32k.sys",
                             file_version:fileVer, vulnerable_range:"Less than 6.1.7601.23963");
  security_message(data:report);
  exit(0);
}
exit(0);
