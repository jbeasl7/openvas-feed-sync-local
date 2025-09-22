# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804107");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2013-2906", "CVE-2013-2923", "CVE-2013-2924", "CVE-2013-2922",
                "CVE-2013-2921", "CVE-2013-2907", "CVE-2013-2908", "CVE-2013-2909",
                "CVE-2013-2910", "CVE-2013-2911", "CVE-2013-2912", "CVE-2013-2913",
                "CVE-2013-2919", "CVE-2013-2918", "CVE-2013-2917", "CVE-2013-2916",
                "CVE-2013-2915", "CVE-2013-2920");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-10-08 06:27:23 +0530 (Tue, 08 Oct 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 (Oct 2013) - Linux");


  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 30.0.1599.66 or later.");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"affected", value:"Google Chrome version before 30.0.1599.66 on Linux");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
service and to spoof the address bar or possibly have unspecified other
impacts via some known or unknown vectors.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55087");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62752");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61885");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/10/stable-channel-update.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

if(version_is_less(version:chromeVer, test_version:"30.0.1599.66"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"30.0.1599.66");
  security_message(port: 0, data: report);
  exit(0);
}
