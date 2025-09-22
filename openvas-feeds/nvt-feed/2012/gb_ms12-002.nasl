# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902784");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-0009");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-01-11 10:54:36 +0530 (Wed, 11 Jan 2012)");
  script_name("Microsoft Windows Object Packager Remote Code Execution Vulnerability (2603381)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45189/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51297");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026494");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-002");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code with
  the privileges of the user running the affected application. Failed exploit
  attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"- Microsoft Windows

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaw is due to the way that Windows registers and uses Windows
  Object Packager. This can be exploited to load an executable file (packager.exe) in an insecure manner
  by tricking a user into opening a Publisher file '.pub' containing an embedded packaged object located
  on a remote WebDAV or SMB share.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-002.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

## MS12-002 Hotfix 2603381
## File information is not available
if(hotfix_missing(name:"2603381") == 1){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
