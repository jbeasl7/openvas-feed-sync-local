# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801448");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-3246", "CVE-2010-3247", "CVE-2010-3249", "CVE-2010-3248",
                "CVE-2010-3250", "CVE-2010-3252", "CVE-2010-3251", "CVE-2010-3253",
                "CVE-2010-3255", "CVE-2010-3254", "CVE-2010-3257", "CVE-2010-3256",
                "CVE-2010-3258", "CVE-2010-3259");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome < 6.0.472.53 Multiple Vulnerabilities (Sep 2010) - Linux");
  script_xref(name:"URL", value:"http://vul.hackerjournals.com/?p=12156");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2010/09/stable-and-beta-channel-updates.html");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause denial of service
  and possibly have unspecified other impact via unknown vectors.");
  script_tag(name:"affected", value:"Google Chrome version prior to 6.0.472.53 on Linux.");
  script_tag(name:"insight", value:"For more information on the vulnerabilities, refer to the links below.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 6.0.472.53 or later.");
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

if(version_is_less(version:chromeVer, test_version:"6.0.472.53")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"6.0.472.53");
  security_message(port: 0, data: report);
}
