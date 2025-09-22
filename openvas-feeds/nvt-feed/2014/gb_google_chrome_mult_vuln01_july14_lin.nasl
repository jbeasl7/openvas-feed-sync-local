# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804729");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2014-3160", "CVE-2014-3162");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-08-01 18:43:05 +0530 (Fri, 01 Aug 2014)");
  script_name("Google Chrome Multiple Vulnerabilities - 01 (Jul 2014) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to An error within SVG component and multiple
unspecified errors exist.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass certain
security restrictions and possibly have other unspecified impact.");
  script_tag(name:"affected", value:"Google Chrome version prior to 36.0.1985.125 on Linux.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome 36.0.1985.125 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60077");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68677");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2014/07/stable-channel-update.html");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"36.0.1985.125"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"36.0.1985.125");
  security_message(port:0, data:report);
  exit(0);
}
