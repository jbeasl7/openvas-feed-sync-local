# SPDX-FileCopyrightText: 2002 SECNAP Network Security, LLC
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11144");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2002-0699");
  script_name("Flaw in Certificate Enrollment Control (Q323172)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 SECNAP Network Security, LLC");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"A vulnerability in the Certificate Enrollment
  ActiveX Control in Microsoft Windows 98, Windows 98 Second Edition, Windows Millennium,
  Windows NT 4.0, Windows 2000, and Windows XP allows remote attackers to delete digital
  certificates on a user's system via HTML.");

  script_tag(name:"impact", value:"Denial of service.");

  script_tag(name:"affected", value:"- Microsoft Windows 98

  - Microsoft Windows 98 (Second Edition)

  - Microsoft Windows Millennium

  - Microsoft Windows NT 4.0

  - Microsoft Windows 2000

  - Microsoft Windows XP");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-048");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(nt:7, win2k:4, xp:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q323172") > 0 )
  security_message(port:0);
