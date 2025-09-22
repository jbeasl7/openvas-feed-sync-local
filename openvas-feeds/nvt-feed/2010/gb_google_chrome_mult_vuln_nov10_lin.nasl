# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801541");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-11-18 06:30:08 +0100 (Thu, 18 Nov 2010)");
  script_cve_id("CVE-2010-4197", "CVE-2010-4198", "CVE-2010-4199", "CVE-2010-4201",
                "CVE-2010-4202", "CVE-2010-4203", "CVE-2010-4204", "CVE-2010-4205",
                "CVE-2010-4206", "CVE-2010-4008");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 18:24:00 +0000 (Fri, 31 Jul 2020)");
  script_name("Google Chrome Multiple Vulnerabilities (Nov 2010) - Linux");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2889");
  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=51602");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2010/11/stable-channel-update.html");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to execute arbitrary code
  in the context of the browser, cause denial-of-service condition, carry out
  spoofing attacks, gain access to sensitive information, and bypass intended security restrictions.");

  script_tag(name:"affected", value:"Google Chrome version prior to 7.0.517.44 on Linux.");

  script_tag(name:"insight", value:"The flaws are due to

  - A use-after-free error related to text editing

  - A memory corruption error when handling an overly large text area

  - A bad cast with the SVG use element

  - An invalid memory read in XPath handling

  - A use-after-free error related to text control selections

  - A integer overflows in font handling on Linux

  - A memory corruption error in libvpx

  - A bad use of destroyed frame objects

  - A type confusions with event objects

  - An out-of-bounds array access when handling SVGs.");

  script_tag(name:"solution", value:"Upgrade to the Google Chrome 7.0.517.44 or later.");

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

if(version_is_less(version:chromeVer, test_version:"7.0.517.44")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"7.0.517.44");
  security_message(port: 0, data: report);
}
