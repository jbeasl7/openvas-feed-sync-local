# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803402");
  script_version("2024-02-21T05:06:27+0000");
  script_cve_id("CVE-2013-0839", "CVE-2013-0840", "CVE-2013-0841", "CVE-2013-0842", "CVE-2013-0843");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:27 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-02-01 16:54:18 +0530 (Fri, 01 Feb 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-02 (Feb 2013) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51935");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57502");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1028030");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/01/stable-channel-update_22.html");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  script_tag(name:"affected", value:"Google Chrome version prior to 24.0.1312.56 on Mac OS X.");

  script_tag(name:"insight", value:"Multiple flaws due to

  - Referring freed memory in canvas font handling.

  - Missing URL validation when opening new windows.

  - Unchecked array index in content blocking functionality.

  - Not properly handling %00 characters in path-names.");

  script_tag(name:"solution", value:"Upgrade to the Google Chrome 24.0.1312.56 or later.");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service or possibly have unspecified other impact.

  Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"24.0.1312.56")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"24.0.1312.56");
  security_message(port: 0, data: report);
}
