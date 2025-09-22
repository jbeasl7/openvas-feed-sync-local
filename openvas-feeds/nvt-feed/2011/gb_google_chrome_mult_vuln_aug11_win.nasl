# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802316");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_cve_id("CVE-2011-2358", "CVE-2011-2359", "CVE-2011-2360", "CVE-2011-2361",
                "CVE-2011-2783", "CVE-2011-2784", "CVE-2011-2785", "CVE-2011-2786",
                "CVE-2011-2787", "CVE-2011-2788", "CVE-2011-2789", "CVE-2011-2790",
                "CVE-2011-2791", "CVE-2011-2792", "CVE-2011-2793", "CVE-2011-2794",
                "CVE-2011-2795", "CVE-2011-2796", "CVE-2011-2797", "CVE-2011-2798",
                "CVE-2011-2799", "CVE-2011-2800", "CVE-2011-2801", "CVE-2011-2802",
                "CVE-2011-2803", "CVE-2011-2804", "CVE-2011-2805", "CVE-2011-2818",
                "CVE-2011-2819");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome Multiple Vulnerabilities (Aug 2011) - Windows");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1025882");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48960");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/08/stable-channel-update.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions, or cause a denial-of-service condition.");
  script_tag(name:"affected", value:"Google Chrome version prior to 13.0.782.107 on Windows.");
  script_tag(name:"insight", value:"For more information on the vulnerabilities refer the below links.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 13.0.782.107 or later.");
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

if(version_is_less(version:chromeVer, test_version:"13.0.782.107")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"13.0.782.107");
  security_message(port: 0, data: report);
}
