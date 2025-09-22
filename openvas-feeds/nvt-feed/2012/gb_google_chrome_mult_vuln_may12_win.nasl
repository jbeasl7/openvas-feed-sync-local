# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802792");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2011-3100", "CVE-2011-3084", "CVE-2011-3099", "CVE-2011-3083",
                "CVE-2011-3097", "CVE-2011-3098", "CVE-2011-3095", "CVE-2011-3094",
                "CVE-2011-3093", "CVE-2011-3092", "CVE-2011-3091", "CVE-2011-3090",
                "CVE-2011-3089", "CVE-2011-3088", "CVE-2011-3087", "CVE-2011-3086",
                "CVE-2011-3085", "CVE-2011-3102");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-05-17 12:28:09 +0530 (Thu, 17 May 2012)");
  script_name("Google Chrome Multiple Vulnerabilities (May 2012) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49194/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53540");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027067");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/05/stable-channel-update.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 19.0.1084.46 on Windows");

  script_tag(name:"solution", value:"Upgrade to the Google Chrome 19.0.1084.46 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"19.0.1084.46")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"19.0.1084.46");
  security_message(port:0, data:report);
}
