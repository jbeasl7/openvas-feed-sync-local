# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900245");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-06-09 17:19:57 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-0252", "CVE-2010-0811");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Data Analyzer and IE Developer Tools ActiveX Control Vulnerability (980195)");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1391");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40490");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-034");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers execute arbitrary code.");

  script_tag(name:"affected", value:"- Microsoft Windows 7

  - Microsoft Windows 2K  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1/2 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior");

  script_tag(name:"insight", value:"An unspecified error exists in the Microsoft Data Analyzer ActiveX control
  (max3activex.dll) and Internet Explorer Developer Tools ActiveX Control
  (iedvtool.dll) when used with Internet Explorer. Attackers can execute
  arbitrary code by tricking a user into visiting a specially crafted web page.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-034.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.

  Workaround:
  Set the killbit for the following CLSIDs,
  {14FD1463-1F3F-4357-9C03-2080B442F503}, {E9CB13DB-20AB-43C5-B283-977C58FB5754}
  {8fe85d00-4647-40b9-87e4-5eb8a52f4759}");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_activex.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

## MS10-034 Hotfix check
if(hotfix_missing(name:"980195") == 0){
  exit(0);
}

## CLSID List
clsids = make_list(
  "{14FD1463-1F3F-4357-9C03-2080B442F503}",
  "{E9CB13DB-20AB-43C5-B283-977C58FB5754}",
  "{8fe85d00-4647-40b9-87e4-5eb8a52f4759}"
 );

foreach clsid (clsids)
{
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
