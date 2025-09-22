# SPDX-FileCopyrightText: 2002 Michael Scheidell
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10926");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-0052");
  script_name("IE VBScript Handling patch (Q318089)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michael Scheidell");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_exclude_keys("SMB/WinXP/ServicePack");

  script_tag(name:"summary", value:"Incorrect VBScript Handling in IE can Allow Web
  Pages to Read Local Files.");

  script_tag(name:"impact", value:"Impact of vulnerability: Information Disclosure");

  script_tag(name:"affected", value:"- Microsoft Internet Explorer 5.01

  - Microsoft Internet Explorer 5.5

  - Microsoft Internet Explorer 6.0");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.

  Also see Microsoft Article Q319847 MS02-009 May Cause Incompatibility Problems Between VBScript and Third-Party Applications");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-009");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4158");

  exit(0);
}

include("smb_nt.inc");

key = "SOFTWARE\Microsoft\Active Setup\Installed Components\{4f645220-306d-11d2-995d-00c04f98bbc9}\";
if( ! registry_key_exists( key:key ) ) exit( 0 );

version = registry_get_sz( key:key, item:"Version" );
if( version && ereg( pattern:"^([1-4],.*|5,([0-5],.*|6,0,([0-9]?[0-9]?[0-9]$|[0-6][0-9][0-9][0-9]|7([0-3]|4([01]|2[0-5])))))", string:version ) ) {
  security_message( port:0, data:"Detected version at " + key + "Version : " + version );
  exit( 0 );
}

exit( 99 );
