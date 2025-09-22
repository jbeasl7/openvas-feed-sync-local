# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900398");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2467");
  script_name("Mozilla Firefox Remote Code Execution Vulnerabilities (Jul 2009) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35914");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35767");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1972");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-35.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attacker to execute arbitrary code
  and results in Denial of Service condition.");

  script_tag(name:"affected", value:"Mozilla Firefox version prior to 3.0.12 and 3.5.1 on Windows.");

  script_tag(name:"insight", value:"Error exists when a page contains a Flash object which presents a slow script
  dialog, and the page is navigated while the dialog is still visible to the
  user, the Flash plugin is unloaded resulting in a crash due to a call to the
  deleted object.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.12 or 3.5.1 or later.");

  script_tag(name:"summary", value:"Firefox browser is prone to Remote Code Execution vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"3.0.12") ||
   version_is_equal(version:ffVer, test_version:"3.5")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}
