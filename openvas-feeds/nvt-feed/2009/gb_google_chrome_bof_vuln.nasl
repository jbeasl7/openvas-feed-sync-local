# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800567");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1441", "CVE-2009-1442");
  script_name("Google Chrome Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=10869");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2009/05/stable-update-security-fix.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"affected", value:"Google Chrome versions prior to 1.0.154.64, version 2.0.159.0 and prior.");
  script_tag(name:"insight", value:"These flaws are due to:

  - a boundary error in nitSkBitmapFromData() function while processing
    vectors related to large bitmap that arrives over the IPC channel.

  - a failure while validating the result of integer multiplication when
    computing image sizes.");
  script_tag(name:"solution", value:"Upgrade to version 1.0.154.64.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Google Chrome is prone to a buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker run arbitrary codes with the
  privilege of logged on user or can craft a special images or canvas to
  execute arbitrary code inside the sandboxed renderer (tab) process and cause
  a tab to crash.");
  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(chromeVer == NULL){
  exit(0);
}

if(version_in_range(version:chromeVer, test_version:"2.0", test_version2:"2.0.159.0")||
   version_is_less (version:chromeVer, test_version:"1.0.154.64")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
