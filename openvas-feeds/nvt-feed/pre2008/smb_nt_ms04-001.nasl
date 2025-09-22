# SPDX-FileCopyrightText: 2004 Jeff Adams
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11992");
  script_version("2024-02-26T14:36:40+0000");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"IAVA", value:"2004-B-0002");
  script_cve_id("CVE-2003-0819");
  script_name("Vulnerability in Microsoft ISA Server 2000 H.323 Filter (816458)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Jeff Adams");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"solution", value:"Users using any of the affected
  products should install the patch immediately.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-001");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9408");

  script_tag(name:"summary", value:"A security vulnerability exists in the H.323 filter for Microsoft Internet
  Security and Acceleration Server 2000 that could allow an attacker
  to overflow a buffer in the Microsoft Firewall Service in Microsoft Internet
  Security and Acceleration Server 2000.");

  script_tag(name:"impact", value:"An attacker who successfully exploited this vulnerability could try to run
  code of their choice in the security context of the Microsoft Firewall Service.
  This would give the attacker complete control over the system.
  The H.323 filter is enabled by default on servers running ISA Server 2000
  computers that are installed in integrated or firewall mode.");

  script_tag(name:"affected", value:"Microsoft ISA 2000 Gold, SP1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

fpc = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc");
if (!fpc) exit(0);

fix = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc/Hotfixes/SP1/291");
if(!fix)security_message(port:0);
