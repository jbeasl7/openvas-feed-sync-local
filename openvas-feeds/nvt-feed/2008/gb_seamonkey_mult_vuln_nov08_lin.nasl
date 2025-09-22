# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800062");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5016",
                "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022",
                "CVE-2008-5023", "CVE-2008-5024", "CVE-2008-5052", "CVE-2008-0017");
  script_name("Mozilla Seamonkey Multiple Vulnerabilities (Nov 2008) - Linux");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-48.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32281");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-49.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-50.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-52.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-54.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-55.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-56.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-57.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2008/mfsa2008-58.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_lin.nasl");
  script_mandatory_keys("Seamonkey/Linux/Ver");

  script_tag(name:"impact", value:"Successful exploitation could result in remote arbitrary code execution,
  bypass security restrictions, spoofing attacks, sensitive information
  disclosure, and JavaScript code that can be executed with the privileges of the signed user.");

  script_tag(name:"affected", value:"Seamonkey version prior to 1.1.13 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Seamonkey version 1.1.13 or later.");

  script_tag(name:"summary", value:"Mozilla Seamonkey is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

smVer = get_kb_item("Seamonkey/Linux/Ver");
if(!smVer){
  exit(0);
}

if(version_is_less(version:smVer, test_version:"1.1.13")){
  report = report_fixed_ver(installed_version:smVer, fixed_version:"1.1.13");
  security_message(port: 0, data: report);
}
