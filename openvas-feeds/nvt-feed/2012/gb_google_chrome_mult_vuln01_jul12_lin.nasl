# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802918");
  script_version("2024-02-26T14:36:40+0000");
  script_cve_id("CVE-2012-2842", "CVE-2012-2843", "CVE-2012-2844");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-26 14:36:40 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-07-24 12:01:56 +0530 (Tue, 24 Jul 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - 01 - (Jul 2012) - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49906");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54386");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027249");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/07/stable-channel-update.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 20.0.1132.57 on Linux");
  script_tag(name:"insight", value:"- A use-after-free error exists within counter handling and within layout
    height tracking.

  - An unspecified error when handling JavaScript within PDFs can be
    exploited to access certain objects.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 20.0.1132.57 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"20.0.1132.57")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"20.0.1132.57");
  security_message(port:0, data:report);
}
