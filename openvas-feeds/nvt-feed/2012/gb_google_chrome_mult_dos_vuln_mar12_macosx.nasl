# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802809");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2011-3031", "CVE-2011-3032", "CVE-2011-3033", "CVE-2011-3034",
                "CVE-2011-3035", "CVE-2011-3036", "CVE-2011-3037", "CVE-2011-3038",
                "CVE-2011-3039", "CVE-2011-3040", "CVE-2011-3041", "CVE-2011-3042",
                "CVE-2011-3043", "CVE-2011-3044");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-03-08 16:21:09 +0530 (Thu, 08 Mar 2012)");
  script_name("Google Chrome Multiple Denial of Service Vulnerabilities (Mar 2012) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48265");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52271");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026759");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/03/chrome-stable-update.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 17.0.963.65 on Mac OS X");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 17.0.963.65 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple denial of service vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"17.0.963.65")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"17.0.963.65");
  security_message(port:0, data:report);
}
