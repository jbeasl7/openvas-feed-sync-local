# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811921");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-11762", "CVE-2017-8694", "CVE-2017-8715", "CVE-2017-8717",
                "CVE-2017-11763", "CVE-2017-11765", "CVE-2017-11769", "CVE-2017-8718",
                "CVE-2017-8726", "CVE-2017-8727", "CVE-2017-11771", "CVE-2017-11772",
                "CVE-2017-11779", "CVE-2017-11780", "CVE-2017-11781", "CVE-2017-11783",
                "CVE-2017-11784", "CVE-2017-11785", "CVE-2017-11790", "CVE-2017-11793",
                "CVE-2017-11798", "CVE-2017-11799", "CVE-2017-11800", "CVE-2017-11802",
                "CVE-2017-11804", "CVE-2017-11808", "CVE-2017-11809", "CVE-2017-11810",
                "CVE-2017-11811", "CVE-2017-11816", "CVE-2017-11817", "CVE-2017-11818",
                "CVE-2017-11822", "CVE-2017-11823", "CVE-2017-11824", "CVE-2017-8689",
                "CVE-2017-8693", "CVE-2017-11814", "CVE-2017-11815", "CVE-2017-13080");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-10-11 08:47:24 +0530 (Wed, 11 Oct 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4042895)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4042895");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A spoofing vulnerability in the Windows implementation of wireless networking (KRACK)

  - The Universal CRT _splitpath was not handling multi byte strings correctly,
    which caused apps to fail when accessing multi byte filenames.

  - The Universal CRT caused the linker (link.exe) to stop working for large
    projects.

  - The MSMQ performance counter (MSMQ Queue) may not populate queue instances
    when the server hosts a clustered MSMQ role.

  - The Lock Workstation policy for smart cards where, in some cases, the system
    doesn't lock when you remove the smart card.

  - Issue with form submissions in Internet Explorer.

  - Issue with URL encoding in Internet Explorer.

  - Issue that prevents an element from receiving focus in Internet Explorer.

  - Issue with the docking and undocking of Internet Explorer windows.

  - Issue with the rendering of a graphics element in Internet Explorer.

  - Issue caused by a pop-up window in Internet Explorer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the security context of the local system, take complete
  control of an affected system, bypass certain security restrictions, gain access
  to potentially sensitive information, conduct a denial-of-service condition and
  gain privileged access.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4042895");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101108");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101100");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101163");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101161");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101109");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101111");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101112");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101084");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101142");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101114");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101116");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101166");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101110");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101140");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101144");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101147");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101149");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101077");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101141");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101125");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101126");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101127");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101130");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101131");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101135");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101137");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101081");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101138");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101094");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101095");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101101");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101122");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101102");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101099");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101128");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101096");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101093");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101136");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101274");
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

if(version_in_range(version:edgeVer, test_version:"11.0.10240.0", test_version2:"11.0.10240.17642"))
{
  report = 'File checked:     ' + sysPath + "\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: 11.0.10240.0 - 11.0.10240.17642\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
