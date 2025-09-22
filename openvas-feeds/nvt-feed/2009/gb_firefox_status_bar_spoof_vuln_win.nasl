# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900446");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-01-28 13:27:12 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0253");
  script_name("Firefox Status Bar Spoofing Vulnerability - Windows");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7842");
  script_xref(name:"URL", value:"http://security-tracker.debian.net/tracker/CVE-2009-0253");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful remote exploitation will let the attacker spoof the status
  bar information and can gain sensitive information by redirecting the authentic user to any malicious URL.");

  script_tag(name:"affected", value:"Mozilla Firefox version 3.0.5 and 2.0.0.18/19 on Windows.");

  script_tag(name:"insight", value:"Firefox doesn't properly handle the crafted URL which is being displayed in
  the user's browser which lets the attacker perform clickjacking attack and
  can spoof the user redirect to a different arbitrary malformed website.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 3.6.3 or later.");

  script_tag(name:"summary", value:"Mozilla Firefox browser is prone to status bar spoofing vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

firefoxVer = get_kb_item("Firefox/Win/Ver");
if(firefoxVer =~ "^(2\.0\.0\.18|2\.0\.0\.19|3\.0\.5)"){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
