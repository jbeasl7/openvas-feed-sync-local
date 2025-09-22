# SPDX-FileCopyrightText: 2002 SECNAP Network Security, LLC
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11146");
  script_version("2024-02-26T14:36:40+0000");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2002-0863", "CVE-2002-0864");
  script_name("Microsoft RDP flaws could allow sniffing and DOS (Q324380)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 SECNAP Network Security, LLC");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"Remote Data Protocol (RDP) version 5.0 in Microsoft
  Windows 2000 and RDP 5.1 in Windows XP does not encrypt the checksums of plaintext session
  data, which could allow a remote attacker to determine the contents of encrypted sessions
  via sniffing, and Remote Data Protocol (RDP) version 5.1 in Windows XP allows remote
  attackers to cause a denial of service (crash) when Remote Desktop is enabled via a PDU
  Confirm Active data packet that does not set the Pattern BLT command.");

  script_tag(name:"impact", value:"Two vulnerabilities: information disclosure, denial of service.");

  script_tag(name:"affected", value:"- Microsoft Windows 2000

  - Microsoft Windows XP");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5410");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5711");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5712");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(xp:1, win2k:4) <= 0 ) exit(0);
if ( hotfix_check_nt_server() <= 0 ) exit(0);
if ( hotfix_missing(name:"Q324380") > 0 )
  security_message(port:0);
