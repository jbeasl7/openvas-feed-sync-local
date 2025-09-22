# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801362");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-06-16 08:26:33 +0200 (Wed, 16 Jun 2010)");
  script_cve_id("CVE-2010-1385", "CVE-2010-1384", "CVE-2010-1390", "CVE-2010-1389",
                "CVE-2010-1391", "CVE-2010-1393", "CVE-2010-1392", "CVE-2010-1394",
                "CVE-2010-1395", "CVE-2010-1396", "CVE-2010-1398", "CVE-2010-1397",
                "CVE-2010-1400", "CVE-2010-1399", "CVE-2010-1401", "CVE-2010-1403",
                "CVE-2010-1402", "CVE-2010-1404", "CVE-2010-1406", "CVE-2010-1405",
                "CVE-2010-1408", "CVE-2010-1409", "CVE-2010-1410", "CVE-2010-1413",
                "CVE-2010-1412", "CVE-2010-1414", "CVE-2010-1416", "CVE-2010-1415",
                "CVE-2010-1417", "CVE-2010-1422", "CVE-2010-1750", "CVE-2010-1749",
                "CVE-2010-1418", "CVE-2010-0544", "CVE-2010-1419", "CVE-2010-1758",
                "CVE-2010-1421", "CVE-2010-1761", "CVE-2010-1759", "CVE-2010-1762",
                "CVE-2010-1770", "CVE-2010-1764", "CVE-2010-1774", "CVE-2010-1771",
                "CVE-2010-2264");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple Safari Multiple Vulnerabilities (Jun 2010)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4196");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40620");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40105");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1373");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jun/1024067.html");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2010/Jun/msg00000.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass certain security
  checks, gain knowledge of sensitive information or execute arbitrary code
  by tricking a user into visiting a specially crafted web page.");

  script_tag(name:"affected", value:"Apple Safari version prior to 5.0 (5.33.16.0) on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.0 or later.");

  script_tag(name:"summary", value:"Apple Safari Web Browser is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Multiple issues are caused by use-after-free, double free, integer
  truncation, heap overflow, memory corruption, uninitialized memory access,
  input validation and implementation errors in ColorSync and WebKit.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"5.33.16.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 5.0 (5.33.16.0)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
