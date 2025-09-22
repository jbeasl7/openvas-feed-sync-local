# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801486");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-10 14:22:58 +0100 (Mon, 10 Jan 2011)");
  script_cve_id("CVE-2007-0675");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Speech Components Voice Recognition Command Execution Vulnerability (950760)");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/1779/references");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22359");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-032");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers execute commands on
  a victim user's computer.");
  script_tag(name:"affected", value:"- Microsoft Windows 2K  Service Pack 4 and prior

  - Microsoft Windows XP  Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 1 and prior

  - Microsoft Windows Server 2008 Service Pack 1/2 and prior");
  script_tag(name:"insight", value:"The flaw is caused by an error in the Speech Components 'sapi.dll' when
  playing audio files in Internet Explorer, which could allow attackers to issue
  certain commands via a malicious audio file and execute arbitrary code on a
  system with the speech recognition feature activated and configured.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-032.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.

  As a workaround set the killbit for the following CLSIDs:

  {47206204-5eca-11d2-960f-00c04f8ee628}, {3bee4890-4fe9-4a37-8c1e-5e7e12791c1f}");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/240797");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_activex.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:2, win2008:3) <= 0){
  exit(0);
}

## MS08-032 Hotfix check
if(hotfix_missing(name:"950760") == 0){
  exit(0);
}

## CLSID List
clsids = make_list(
  "{47206204-5eca-11d2-960f-00c04f8ee628}",
  "{3bee4890-4fe9-4a37-8c1e-5e7e12791c1f}"
);

foreach clsid (clsids)
{
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
