# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812331");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-11885", "CVE-2017-11907", "CVE-2017-11909", "CVE-2017-11910",
                "CVE-2017-11911", "CVE-2017-11912", "CVE-2017-11886", "CVE-2017-11887",
                "CVE-2017-11888", "CVE-2017-11889", "CVE-2017-11890", "CVE-2017-11893",
                "CVE-2017-11894", "CVE-2017-11895", "CVE-2017-11899", "CVE-2017-11901",
                "CVE-2017-11903", "CVE-2017-11905", "CVE-2017-11906", "CVE-2017-11913",
                "CVE-2017-11914", "CVE-2017-11918", "CVE-2017-11919", "CVE-2017-11927",
                "CVE-2017-11930");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-12-13 08:56:15 +0530 (Wed, 13 Dec 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4053578)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4053578");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in RPC if the server has Routing and Remote Access enabled.

  - An error when Internet Explorer improperly accesses objects in memory.

  - An error when Internet Explorer improperly handles objects in memory.

  - An error when the Windows its:// protocol handler unnecessarily sends traffic
    to a remote site in order to determine the zone of a provided URL.

  - An error when Microsoft Edge improperly accesses objects in memory.

  - An error in the way that the scripting engine handles objects in memory in
    Microsoft Edge.

  - An error in the way the scripting engine handles objects in memory in Microsoft
    browsers.

  - A security feature bypass exists when Device Guard incorrectly validates an
    untrusted file.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, gain the same user rights as the current user, obtain
  sensitive information to further compromise the user's system, a brute-force
  to disclose the NTLM hash password and make an unsigned file appear to be signed.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1511 x32/x64.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4053578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102055");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102085");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102086");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102087");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102092");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102062");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102063");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102065");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102080");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102082");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102081");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102053");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102054");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102077");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102046");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102091");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102088");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102089");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.1294"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.10586.0 - 11.0.10586.1294");
  security_message(data:report);
  exit(0);
}
exit(0);
