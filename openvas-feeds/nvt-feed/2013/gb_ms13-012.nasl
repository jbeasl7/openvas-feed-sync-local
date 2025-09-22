# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902948");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-0393", "CVE-2013-0418");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-02-13 10:16:56 +0530 (Wed, 13 Feb 2013)");
  script_name("Microsoft Exchange Server Remote Code Execution Vulnerabilities (2809279)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2809279");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57357");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57364");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-012");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to cause a denial of service
  condition or run arbitrary code as LocalService on the affected Exchange
  server.");
  script_tag(name:"affected", value:"- Microsoft Exchange Server 2007 Service Pack 3

  - Microsoft Exchange Server 2010 Service Pack 2");
  script_tag(name:"insight", value:"Flaws are in Microsoft Exchange Server WebReady Document Viewing and will
  allow remote code execution in the security context of the transcoding service
  on the Exchange server if a user previews a specially crafted file using
  Outlook Web App (OWA)");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS13-012.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");



if(!registry_key_exists(key:"SOFTWARE\Microsoft\Exchange")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach version (make_list("Microsoft Exchange v14", "Microsoft Exchange"))
{
  key = key + version;
  exchangePath = registry_get_sz(key:key, item:"InstallLocation");

  if(exchangePath)
  {
    exeVer = fetch_file_version(sysPath:exchangePath,
             file_name:"Bin\ExSetup.exe");

    if(exeVer)
    {
      if(version_is_less(version:exeVer, test_version:"8.3.298.3") ||
         version_in_range(version:exeVer, test_version:"14.2", test_version2:"14.2.342.2"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
