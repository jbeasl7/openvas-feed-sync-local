# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805951");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2015-2434", "CVE-2015-2471", "CVE-2015-2440");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2015-08-12 10:29:39 +0530 (Wed, 12 Aug 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office XML Core Services Information Disclosure Vulnerability (3080129)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-084.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to:

  - An error in  Microsoft XML Core Services which allows forceful use of Secure
  Sockets Layer (SSL) 2.0.

  - An error in Microsoft XML Core Services which exposes memory addresses not
  intended for public disclosure.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct man-in-the-middle (MiTM) attack and gain access to
  sensitive data.");

  script_tag(name:"affected", value:"- Microsoft Office 2007 Service Pack 3 and prior

  - Microsoft InfoPath 2007 Service Pack 3 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2825645");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76232");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76257");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76229");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3080129");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms15-084");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2007
if(!officeVer || officeVer !~ "^12\."){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"CommonFilesDir");
if(path)
{
  filePath = path + "\Microsoft Shared\OFFICE12" ;

  dllVer = fetch_file_version(sysPath:filePath, file_name:"Msxml5.dll");

  if(dllVer && (version_is_less(version:dllVer, test_version:"5.20.1104.0")))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

