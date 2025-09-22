# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802882");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2012-2815", "CVE-2012-2817", "CVE-2012-2818", "CVE-2012-2819",
                "CVE-2012-2820", "CVE-2012-2821", "CVE-2012-2822", "CVE-2012-2823",
                "CVE-2012-2824", "CVE-2012-2825", "CVE-2012-2826", "CVE-2012-2828",
                "CVE-2012-2829", "CVE-2012-2830", "CVE-2012-2831", "CVE-2012-2832",
                "CVE-2012-2833", "CVE-2012-2834", "CVE-2012-2827");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-07-04 14:54:30 +0530 (Wed, 04 Jul 2012)");
  script_name("Google Chrome Multiple Vulnerabilities (Jul 2012) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49724");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54203");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/06/stable-channel-update_26.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 20.0.1132.43 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to the Google Chrome 20.0.1132.43 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"20.0.1132.43")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"20.0.1132.43");
  security_message(port:0, data:report);
}
