# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802383");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2010-5082");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-01-19 16:17:52 +0530 (Thu, 19 Jan 2012)");
  script_name("Microsoft Windows Color Control Panel Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"http://www.koszyk.org/b/archives/82");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44157");
  script_xref(name:"URL", value:"http://shinnai.altervista.org/exploits/SH-006-20100914.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"impact", value:"Successful attempt could allow local attackers to bypass security
  restrictions and gain the privileges.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 SP2.");

  script_tag(name:"insight", value:"The flaw is due to an error in the Color Control Panel, which
  allows attackers to gain privileges via a Trojan horse sti.dll file in the current working directory.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"Microsoft Windows Server 2008 SP2 is prone to a privilege
  escalation vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.902791.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-012");

  exit(0);
}

exit(66);
