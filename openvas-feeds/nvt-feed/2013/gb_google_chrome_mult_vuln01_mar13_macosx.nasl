# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803315");
  script_version("2024-02-21T05:06:27+0000");
  script_cve_id("CVE-2013-0879", "CVE-2013-0880", "CVE-2013-0881", "CVE-2013-0882",
                "CVE-2013-0883", "CVE-2013-0884", "CVE-2013-0885", "CVE-2013-0886",
                "CVE-2013-0887", "CVE-2013-0888", "CVE-2013-0889", "CVE-2013-0890",
                "CVE-2013-0891", "CVE-2013-0892", "CVE-2013-0893", "CVE-2013-0894",
                "CVE-2013-0895", "CVE-2013-0896", "CVE-2013-0897", "CVE-2013-0898",
                "CVE-2013-0899", "CVE-2013-0900", "CVE-2013-2268");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:27 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-03-01 10:40:56 +0530 (Fri, 01 Mar 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 (Mar 2013) - Mac OS X");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/438026.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58101");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/52320");
  script_xref(name:"URL", value:"http://www.dhses.ny.gov/ocs/advisories/2013/2013-021.cfm");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/02/stable-channel-update_21.html");

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in
  the context of the browser, bypass security restrictions, cause
  denial-of-service condition or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"Google Chrome version prior to 25.0.1364.99 on Mac OS X.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to the Google Chrome 25.0.1364.99 or later.");

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

if(version_is_less(version:chromeVer, test_version:"25.0.1364.99")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"25.0.1364.99");
  security_message(port: 0, data: report);
  exit(0);
}
