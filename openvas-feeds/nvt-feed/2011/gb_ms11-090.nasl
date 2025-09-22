# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902598");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2011-3397");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-12-14 11:11:11 +0530 (Wed, 14 Dec 2011)");
  script_name("Microsoft Windows Time Component Remote Code Execution Vulnerability (2618451)");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026408");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50970");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-090");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation allows execution of arbitrary code when viewing a
  specially crafted web page using Internet Explorer.");
  script_tag(name:"affected", value:"- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error in the time component in
  DATIME.DLL, which allows remote attackers to execute arbitrary code via
  a crafted web site.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-090.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_activex.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:2, win2008:3) <= 0){
  exit(0);
}

## MS11-090 Hotfix check
if(hotfix_missing(name:"2618451") == 0){
  exit(0);
}

## CLSID List
clsids = make_list(
  "{33FDA1EA-80DF-11d2-B263-00A0C90D6111}",
  "{476c391c-3e0d-11d2-b948-00c04fa32195}"
 );

foreach clsid (clsids)
{
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
