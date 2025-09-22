# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802358");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2011-4691", "CVE-2011-4692");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-12-09 12:30:25 +0530 (Fri, 09 Dec 2011)");
  script_name("Google Chrome Cache History Information Disclosure Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47127");
  script_xref(name:"URL", value:"http://lcamtuf.coredump.cx/cachetime/");
  script_xref(name:"URL", value:"http://sip.cs.princeton.edu/pub/webtiming.pdf");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
sensitive information about visited web page.");
  script_tag(name:"affected", value:"Google Chrome version 15.0.874.121 and prior on Windows");
  script_tag(name:"insight", value:"Multiple flaws are due to improper capturing of data about the
times of Same Origin Policy violations during IFRAME and image loading attempts,
allows attacker to enumerate visited sites via crafted JavaScript code.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Google Chrome is prone to information disclosure vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less_equal(version:chromeVer, test_version:"15.0.874.121")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
