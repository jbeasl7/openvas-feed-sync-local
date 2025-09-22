# SPDX-FileCopyrightText: 2003 Trevor Hemsley
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11413");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0109");
  script_xref(name:"IAVA", value:"2003-A-0005");
  script_name("Unchecked Buffer in ntdll.dll (Q815021)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Trevor Hemsley");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"The remote host is vulnerable to a flaw in ntdll.dll
  which may allow an attacker to gain system privileges, by exploiting it through, for
  instance, WebDAV in IIS5.0 (other services could be exploited, locally and/or remotely)");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.

  Note : Microsoft recommends (quoted from advisory) that:

  If you have not already applied the MS03-007 patch from this bulletin, Microsoft recommends you apply the MS03-013
  patch as it also corrects an additional vulnerability.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-007");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7116");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-013");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(nt:7, xp:2, win2k:4) <= 0 ) exit(0);

if ( hotfix_missing(name:"Q811493") > 0 &&
     hotfix_missing(name:"Q815021") > 0 &&
     hotfix_missing(name:"840987") > 0 )
{
  if ( hotfix_check_sp(xp:2) > 0 && hotfix_missing(name:"890859") <= 0 ) exit(0);
  security_message(port:0);
}
