# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801668");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_cve_id("CVE-2010-4575", "CVE-2010-4576", "CVE-2010-4577",
                "CVE-2010-4578");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 02:39:54 +0000 (Fri, 02 Feb 2024)");
  script_name("Google Chrome Multiple Vulnerabilities (Dec 2010) - Linux");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=60761");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=63529");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=63866");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=64959");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2010/12/stable-beta-channel-updates_13.html");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 8.0.552.224 on Linux");
  script_tag(name:"insight", value:"- The ThemeInstalledInfoBarDelegate::Observe function in browser/extensions/
    theme_installed_infobar_delegate.cc does not properly handle incorrect tab
    interaction by an extension.

  - browser/worker_host/message_port_dispatcher.cc does not properly handle
    certain postMessage calls, which allows remote attackers to cause a denial
    of service via crafted JavaScript code that creates a web worker.

  - Out-of-bounds read error in CSS parsing allows remote attackers to cause a
    denial of service.

  - Stale pointers in cursor handling allows remote attackers to cause a denial
    of service.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 8.0.552.224 or later.");
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

if(version_is_less(version:chromeVer, test_version:"8.0.552.224")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"8.0.552.224");
  security_message(port: 0, data: report);
}
