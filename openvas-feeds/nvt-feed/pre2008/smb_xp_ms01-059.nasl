# SPDX-FileCopyrightText: 2002 Michael Scheidell
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10835");
  script_version("2024-04-11T05:05:26+0000");
  script_tag(name:"last_modification", value:"2024-04-11 05:05:26 +0000 (Thu, 11 Apr 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0876", "CVE-2001-0877");
  script_name("Microsoft Windows XP Multiple Vulnerabilities (MS01-059, Q315000)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michael Scheidell");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"Microsoft Windows XP is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2001-0876: Buffer overflow in Universal Plug and Play (UPnP) allows remote attackers to
  execute arbitrary code via a NOTIFY directive with a long Location URL.

  - CVE-2001-0877: Universal Plug and Play (UPnP) allows remote attackers to cause a denial of
  service via a spoofed SSDP advertisement that causes the client to connect to a service on another
  machine that generates a large amount of traffic (e.g., chargen), or via a spoofed SSDP
  announcement to broadcast or multicast addresses, which could cause all UPnP clients to send
  traffic to a single target system.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-059");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3723");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if( hotfix_check_sp( xp:1 ) <= 0 )
  exit( 0 );

if( hotfix_missing( name:"Q315000" ) > 0 ) {
  security_message(port:0);
  exit( 0 );
}

exit( 99 );
