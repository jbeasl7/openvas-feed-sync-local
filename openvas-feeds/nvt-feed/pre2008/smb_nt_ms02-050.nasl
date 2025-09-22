# SPDX-FileCopyrightText: 2002 SECNAP Network Security, LLC
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11145");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-1183", "CVE-2002-0862");
  script_name("Certificate Validation Flaw Could Enable Identity Spoofing (Q328145)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 SECNAP Network Security, LLC");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"Hotfix to fix Certificate Validation Flaw (Q329115)
  is not installed.");

  script_tag(name:"insight", value:"The vulnerability could enable an attacker who had a valid end-entity certificate to issue a
  subordinate certificate that, although bogus, would nevertheless pass validation. Because
  CryptoAPI is used by a wide range of applications, this could enable a variety of identity
  spoofing attacks.");

  script_tag(name:"impact", value:"Identity spoofing.");

  script_tag(name:"affected", value:"- Microsoft Windows 98

  - Microsoft Windows 98 (Second Edition)

  - Microsoft Windows Me

  - Microsoft Windows NT 4.0

  - Microsoft Windows NT 4.0 (Terminal Server Edition)

  - Microsoft Windows 2000

  - Microsoft Windows XP

  - Microsoft Office for Mac

  - Microsoft Internet Explorer for Mac

  - Microsoft Outlook Express for Mac");

  script_tag(name:"solution", value:"The vendor has released updates, please see the references for more information.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5410");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(nt:7, win2k:4, xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q329115") > 0  )
  security_message(port:0);

