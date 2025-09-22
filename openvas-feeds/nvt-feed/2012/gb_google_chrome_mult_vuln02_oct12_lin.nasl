# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802474");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2012-5112", "CVE-2012-5376");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-27 17:19:00 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"creation_date", value:"2012-10-15 12:50:25 +0530 (Mon, 15 Oct 2012)");
  script_name("Google Chrome Multiple Vulnerabilities-02 (Oct 2012) - Linux");
  script_xref(name:"URL", value:"http://blog.chromium.org/2012/10/pwnium-2-results-and-wrap-up_10.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55867");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2012/10/stable-channel-update_6105.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code
  and cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 22.0.1229.94 on Linux");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - Use-after-free error in the SVG implementation in WebKit, allows remote
    attackers to execute arbitrary code via unspecified vectors.

  - An error in Inter-process Communication (IPC) implementation, allows
    remote attackers to bypass intended sandbox restrictions and write to
    arbitrary files by leveraging access to a renderer process.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 22.0.1229.94 or later.");
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

if(version_is_less(version:chromeVer, test_version:"22.0.1229.94")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"22.0.1229.94");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
