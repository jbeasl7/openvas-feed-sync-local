# SPDX-FileCopyrightText: 2002 Michael Scheidell
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10866");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-0057");
  script_name("XML Core Services patch (Q318203)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michael Scheidell");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"XMLHTTP Control Can Allow Access to Local Files.");

  script_tag(name:"insight", value:"A flaw exists in how the XMLHTTP control applies IE security zone settings to a
  redirected data stream returned in response to a request for data from a web site.

  A vulnerability results because an attacker could seek to exploit this flaw and
  specify a data source that is on the user's local system. The attacker could then
  use this to return information from the local system to the attacker's web site.");

  script_tag(name:"impact", value:"Attacker can read files on client system.");

  script_tag(name:"affected", value:"- Microsoft XML Core Services versions 2.6, 3.0, and 4.0. An affected version of XML Core Services is also shipped as part of the following products:

  - Microsoft Windows XP

  - Microsoft Internet Explorer 6.0

  - Microsoft SQL Server 2000 (note: versions earlier than 2.6 are not affected files affected include msxml[2-4].dll and are found in the system32 directory. This might be false positive if you have earlier version)");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-008");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3699");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(nt:7, win2k:5, xp:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"Q832483") > 0 &&
     hotfix_missing(name:"Q318202") > 0 &&
     hotfix_missing(name:"Q318203") > 0 &&
     hotfix_missing(name:"Q317244") > 0 )
  security_message(port:0);
