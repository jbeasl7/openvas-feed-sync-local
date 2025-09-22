# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800442");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-01-22 16:43:14 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 14:30:29 +0000 (Wed, 24 Jul 2024)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-0232");
  script_name("Microsoft Windows GP Trap Handler Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"http://isc.sans.org/diary.html?storyid=8050");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0179");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/979682.mspx");
  script_xref(name:"URL", value:"http://foro.elhacker.net/bugs_y_exploits/0day_m_iquestcve20100232-t281831.0.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass
  certain security restrictions or can gain escalated privileges via specially crafted attack.");

  script_tag(name:"affected", value:"- Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2000 Service Pack 4 and prior

  - Microsoft Windows Server 2003 Service Pack 2 and prior");

  script_tag(name:"insight", value:"This issue is due to the kernel not properly handling certain
  exceptions when setting up a VDM (Virtual DOS Machine) context, which
  allows users to gain kernel privileges by setting up a crafted 'DM_TIB'
  in their 'TEB' and reach the 'Ki386BiosCallReturnAddress()' function via
  the '#GP trap handler (nt!KiTrap0D)'.");

  script_tag(name:"summary", value:"Microsoft Windows operating system is prone to a privilege escalation
  vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.900740.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

exit(66);
