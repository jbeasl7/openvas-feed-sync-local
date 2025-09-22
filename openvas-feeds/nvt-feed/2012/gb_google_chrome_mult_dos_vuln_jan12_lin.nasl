# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802375");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2011-3919", "CVE-2011-3921", "CVE-2011-3922");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-01-10 15:15:57 +0530 (Tue, 10 Jan 2012)");
  script_name("Google Chrome Multiple Denial of Service Vulnerabilities (Jan 2012) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47449/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51300");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2012/01/stable-channel-update.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code,
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 16.0.912.75 on Linux");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A use-after-free error when the handling of animation frames.

  - A boundary error within the 'xmlStringLenDecodeEntities()' function of
    libxml2

  - A stack based buffer overflow error in glyph handling.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 16.0.912.75 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple denial of service vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"16.0.912.75")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"16.0.912.75");
  security_message(port:0, data:report);
}
