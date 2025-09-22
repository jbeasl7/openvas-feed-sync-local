# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800176");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0806");
  script_name("Microsoft Internet Explorer RCE Vulnerability (981374)");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-018");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38615");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Mar/1023699.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/981374.mspx");
  script_xref(name:"URL", value:"http://www.trustedsource.org/blog/388/Targeted-Internet-Explorer-0day-Attack-Announced-CVE-2010-0806");
  script_xref(name:"URL", value:"http://www.freevirusremovalguide.com/18401/targeted-internet-explorer-0day-attack-announced-cve-2010-0806/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x and 7.x.");

  script_tag(name:"insight", value:"The flaw exists due to an invalid pointer reference being made within
  Internet Explorer. In specially-crafted attack, attempting to access a freed
  object, it can be caused to execute arbitrary code.");

  script_tag(name:"summary", value:"Internet Explorer is prone to a remote code execution (RCE) vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.902155.");

  script_tag(name:"solution", value:"Apply the update from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

exit(66);
