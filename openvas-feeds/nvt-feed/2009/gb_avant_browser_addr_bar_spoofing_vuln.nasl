# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800871");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-02 11:50:45 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3004");
  script_name("Avant Browser Address Bar Spoofing Vulnerability");
  script_xref(name:"URL", value:"http://lostmon.blogspot.com/2009/08/multiple-browsers-fake-url-folder-file.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_avant_browser_detect.nasl");
  script_mandatory_keys("AvantBrowser/Ver");
  script_tag(name:"impact", value:"Successful exploitation lets the attackers to spoof parts of the
address bar and modify page content on a host that a user may consider partly
trusted.");
  script_tag(name:"affected", value:"Avant Browser version 11.7 Build 35 and 36 on Windows.");
  script_tag(name:"insight", value:"Address bar can be spoofed via 'window.open()' with a relative
URI, to show an arbitrary URL on the web site visited by the victim, as
demonstrated by a visit to an attacker-controlled web page, which triggers a
spoofed login form for the site containing that page.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Avant Browser is prone to Address Bar Spoofing vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

abVer = get_kb_item("AvantBrowser/Ver");
if(!abVer){
  exit(0);
}

if(version_is_equal(version:abVer, test_version:"11.7.0.35")||
   version_is_equal(version:abVer, test_version:"11.7.0.36")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
