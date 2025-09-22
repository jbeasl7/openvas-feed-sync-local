# SPDX-FileCopyrightText: 2002 Michael Scheidell
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10943");
  script_version("2024-06-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-06-06 05:05:36 +0000 (Thu, 06 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  # Those are the "CAN-2002-xyz" ones from MS02-062
  script_cve_id("CVE-2002-0869", "CVE-2002-1182", "CVE-2002-1180", "CVE-2002-1181");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Microsoft Internet Information Services (IIS) Multiple Vulnerabilities (Q327696, MS02-062)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Michael Scheidell");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-062");

  script_tag(name:"summary", value:"Microsoft Internet Information Services (IIS) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the Cumulative Patch for IIS (Q327696) is
  installed.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2002-0869: Out of Process Privilege Elevation

  - CVE-2002-1182: WebDAV Denial of Service

  - CVE-2002-1180: Script Source Access Vulnerability

  - CVE-2002-1181: Cross-site Scripting in IIS Administrative Pages");

  script_tag(name:"affected", value:"- Microsoft Internet Information Services 4.0

  - Microsoft Internet Information Services 5.0

  - Microsoft Internet Information Services 5.1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if(hotfix_check_iis_installed() <= 0)
  exit(0);

if(hotfix_check_sp(nt:7, win2k:3, xp:1) <= 0)
  exit(0);

if(hotfix_missing(name:"Q811114") > 0 &&
   hotfix_missing(name:"Q327696") > 0) {
  security_message(port:0);
  exit(0);
}

exit(99);
