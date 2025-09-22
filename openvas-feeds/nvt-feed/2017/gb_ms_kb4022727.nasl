# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811196");
  script_version("2025-04-07T05:39:52+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-0193", "CVE-2017-8473", "CVE-2017-8474", "CVE-2017-8527",
                "CVE-2017-0218", "CVE-2017-0219", "CVE-2017-0282", "CVE-2017-8475",
                "CVE-2017-8476", "CVE-2017-8529", "CVE-2017-8530", "CVE-2017-8531",
                "CVE-2017-0283", "CVE-2017-0284", "CVE-2017-8477", "CVE-2017-8478",
                "CVE-2017-8532", "CVE-2017-0285", "CVE-2017-8479", "CVE-2017-8480",
                "CVE-2017-8533", "CVE-2017-8543", "CVE-2017-0287", "CVE-2017-0288",
                "CVE-2017-8481", "CVE-2017-8482", "CVE-2017-8483", "CVE-2017-8544",
                "CVE-2017-8547", "CVE-2017-8548", "CVE-2017-8549", "CVE-2017-0289",
                "CVE-2017-0291", "CVE-2017-0292", "CVE-2017-8484", "CVE-2017-8485",
                "CVE-2017-0294", "CVE-2017-0296", "CVE-2017-8489", "CVE-2017-0297",
                "CVE-2017-0298", "CVE-2017-8490", "CVE-2017-8491", "CVE-2017-0299",
                "CVE-2017-0300", "CVE-2017-8460", "CVE-2017-8492", "CVE-2017-8493",
                "CVE-2017-8494", "CVE-2017-8462", "CVE-2017-8464", "CVE-2017-8470",
                "CVE-2017-8471", "CVE-2017-8522", "CVE-2017-8523", "CVE-2017-8524",
                "CVE-2017-8465", "CVE-2017-8466", "CVE-2017-8468", "CVE-2017-8517",
                "CVE-2017-8554", "CVE-2017-8575", "CVE-2017-8518");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-07 05:39:52 +0000 (Mon, 07 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-04 20:28:18 +0000 (Fri, 04 Apr 2025)");
  script_tag(name:"creation_date", value:"2017-06-15 16:09:05 +0530 (Thu, 15 Jun 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4022727)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4022727");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Users cannot print enhanced metafiles (EMF) or documents containing bitmaps
    rendered out of bounds using the BitMapSection (DIBSection) function.

  - Displays turn off unexpectedly even when 'Turn off display' is set to 'Never' in
    Power Options.

  - certutil.exe can no longer generate an export file (.epf) when attempting to
    recover a key for a version 1 certificate.

  - MSI files will no longer install when Device Guard is enabled.

  - A thin client becomes unusable and unresponsive when Unified Write Filter
   (UWF) with DISK mode is enabled causing NTFS errors with ID: 55 & ID: 130
   to be logged in the Event Logs.

  - Microsoft Edge improperly accesses objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain the same user rights as the current user. If the current user is logged
  on with administrative user rights, an attacker who successfully exploited the
  vulnerability could take control of an affected system. An attacker could then
  install programs. View, change, or delete data, or create new accounts with full
  user rights.");

  script_tag(name:"affected", value:"Microsoft Windows 10 for 32bit/x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4022727");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98878");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98852");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98902");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98933");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98897");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98898");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98885");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98903");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98953");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98863");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98819");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98920");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98918");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98854");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98845");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98820");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98914");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98856");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98857");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98821");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98824");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98922");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98923");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98862");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98859");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98826");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98932");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98954");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98955");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98929");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98835");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98836");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98847");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98860");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98837");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98839");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98865");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98840");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98867");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98869");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98884");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98901");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98887");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98870");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98850");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98855");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98900");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98818");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98848");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98849");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98926");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98928");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98930");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98843");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98844");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98846");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98895");
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

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"Edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.10240.0", test_version2:"11.0.10240.17442"))
{
  report = 'File checked:     ' + sysPath + "\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: 11.0.10240.0 - 11.0.10240.17442\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
