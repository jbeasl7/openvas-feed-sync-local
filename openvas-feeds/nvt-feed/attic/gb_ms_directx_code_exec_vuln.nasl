# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900097");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1537");
  script_name("Microsoft DirectShow RCE Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-028");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35139");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/971778");

  script_tag(name:"impact", value:"Attacker who successfully exploit this flaw could take complete control of
  an affected system.");

  script_tag(name:"affected", value:"DirectX 7.0 8.1 and 9.0* on Microsoft Windows 2K

  DirectX 9.0 on Microsoft Windows XP and 2K3");

  script_tag(name:"insight", value:"Microsoft DirectShow fails to handle supported QuickTime format files. This
  could allow code execution if a user opened a specially crafted QuickTime
  media file when a user is logged on with administrative user rights.");

  script_tag(name:"summary", value:"Microsoft DirectShow is prone to a remote code execution (RCE) vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.900588.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
