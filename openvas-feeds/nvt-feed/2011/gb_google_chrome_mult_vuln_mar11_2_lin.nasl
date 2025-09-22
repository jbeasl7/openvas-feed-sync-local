# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901198");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_cve_id("CVE-2011-1291", "CVE-2011-1292", "CVE-2011-1293",
                "CVE-2011-1294", "CVE-2011-1295", "CVE-2011-1296");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome < 10.0.648.204 Multiple Vulnerabilities (Mar 2011) - Linux");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/03/stable-channel-update.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47029");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser or cause denial-of-service condition.");
  script_tag(name:"affected", value:"Google Chrome version prior to 10.0.648.204 on Linux");
  script_tag(name:"insight", value:"- A buffer overflow error in base string handling.

  - An use-after-free error in the frame-loader implementation.

  - An Use-after-free error in the HTMLCollection implementation.

  - An error in the processing of CSS which leaves stale pointers
    behind.

  - An unspecified error related to broken node-hierarchy which leads to DOM
    tree corruption.

  - An error in the processing of SVG text which leaves stale pointers behind.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 10.0.648.204 or later.");
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

if(version_is_less(version:chromeVer, test_version:"10.0.648.204")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"10.0.648.204");
  security_message(port: 0, data: report);
}
