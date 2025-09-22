# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803968");
  script_version("2025-01-17T15:39:18+0000");
  script_cve_id("CVE-2013-6802", "CVE-2013-6632");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-11-25 14:00:39 +0530 (Mon, 25 Nov 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-02 (Nov 2013) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 31.0.1650.57 or later.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Unspecified security bypass vulnerability in sandbox restrictions

  - Unspecified memory-corruption vulnerabilities");
  script_tag(name:"affected", value:"Google Chrome version prior to 31.0.1650.57 on Linux");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
service condition, bypass sandbox protection and execute arbitrary code or
possibly have other impact via unknown vectors.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/11/stable-channel-update_14.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63727");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63729");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!my_app_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:my_app_ver, test_version:"31.0.1650.57"))
{
  report = report_fixed_ver(installed_version:my_app_ver, fixed_version:"31.0.1650.57");
  security_message(port: 0, data: report);
  exit(0);
}
