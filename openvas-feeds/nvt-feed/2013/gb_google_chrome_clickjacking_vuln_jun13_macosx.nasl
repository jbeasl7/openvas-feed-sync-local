# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803676");
  script_version("2024-02-21T05:06:27+0000");
  script_cve_id("CVE-2013-2866");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:27 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-06-24 12:10:48 +0530 (Mon, 24 Jun 2013)");
  script_name("Google Chrome Clickjacking Vulnerability (Jun 2013) - Mac OS X");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1028694");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/06/stable-channel-update_18.html");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive information
  and conduct clickjacking attacks against the user's Flash configuration.");
  script_tag(name:"affected", value:"Google Chrome version prior to 27.0.1453.116 on Mac OS X.");
  script_tag(name:"insight", value:"Flaw within Flash plug-in which does not properly determine whether a user
  wishes to permit camera or microphone access by a Flash application.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 27.0.1453.116 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to Clickjacking vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"27.0.1453.116")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"27.0.1453.116");
  security_message(port: 0, data: report);
}
