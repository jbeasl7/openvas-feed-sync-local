# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801856");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_cve_id("CVE-2011-1107", "CVE-2011-1108", "CVE-2011-1109", "CVE-2011-1110",
                "CVE-2011-1111", "CVE-2011-1112", "CVE-2011-1114", "CVE-2011-1115",
                "CVE-2011-1116", "CVE-2011-1117", "CVE-2011-1118", "CVE-2011-1119",
                "CVE-2011-1120", "CVE-2011-1121", "CVE-2011-1122", "CVE-2011-1123",
                "CVE-2011-1124", "CVE-2011-1125");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Google Chrome < 9.0.597.107 Multiple Vulnerabilities (Mar 2011) - Linux");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/02/stable-channel-update_28.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46614");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code
  in the context of the browser, perform spoofing attacks, or cause denial of
  service condition.");
  script_tag(name:"affected", value:"Google Chrome version prior to 9.0.597.107 on Linux");
  script_tag(name:"insight", value:"- An unspecified error related to the URL bar can be exploited to conduct
    spoofing attacks.

  - An unspecified error exists in the handling of JavaScript dialogs.

  - An error when handling stylesheet nodes can lead to a stale pointer.

  - An error when handling key frame rules can lead to a stale pointer.

  - An unspecified error exists in the handling of form controls.

  - An unspecified error exists while rendering SVG content.

  - An unspecified error in table handling can lead to a stale node.

  - An unspecified error in table rendering can lead to a stale pointer.

  - An unspecified error in SVG animations can lead to a stale pointer.

  - An unspecified error when handling XHTML can lead to a stale node.

  - An unspecified error exists in the textarea handling.

  - An unspecified error when handling device orientation can lead to a stale
    pointer.

  - An unspecified error in WebGL can be exploited to cause out-of-bounds reads.

  - An integer overflow exists in the textarea handling.

  - An unspecified error in WebGL can be exploited to cause out-of-bounds reads.

  - An unspecified error can lead to exposure of internal extension functions.

  - A use-after-free error exists within the handling of blocked plug-ins.

  - An unspecified error when handling layouts can lead to a stale pointer.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 9.0.597.107 or later.");
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

if(version_is_less(version:chromeVer, test_version:"9.0.597.107")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"9.0.597.107");
  security_message(port: 0, data: report);
}
