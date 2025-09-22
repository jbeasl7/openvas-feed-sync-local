# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902543");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_cve_id("CVE-2010-1383", "CVE-2010-1420", "CVE-2011-0214", "CVE-2011-0215",
                "CVE-2011-0216", "CVE-2011-0217", "CVE-2011-0218", "CVE-2011-0219",
                "CVE-2011-0221", "CVE-2011-0222", "CVE-2011-0223", "CVE-2011-0225",
                "CVE-2011-0232", "CVE-2011-0233", "CVE-2011-0234", "CVE-2011-0235",
                "CVE-2011-0237", "CVE-2011-0238", "CVE-2011-0240", "CVE-2011-0241",
                "CVE-2011-0242", "CVE-2011-0244", "CVE-2011-0253", "CVE-2011-0254",
                "CVE-2011-0255", "CVE-2011-1288", "CVE-2011-1453", "CVE-2011-1457",
                "CVE-2011-1462", "CVE-2011-1774", "CVE-2011-1797", "CVE-2011-3443");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple Safari Multiple Vulnerabilities (Jul 2011)");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4808");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48820");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48823");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48825");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48827");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48828");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48831");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48832");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48833");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48837");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48839");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48840");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48841");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48842");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48843");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48844");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48845");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48846");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48847");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48848");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48849");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48850");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48851");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48852");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48854");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48855");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48856");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48857");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48859");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51035");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2011/Jul/msg00002.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  script_tag(name:"impact", value:"Successful exploitation may result in information disclosure, remote code
  execution, denial of service, or other consequences.");

  script_tag(name:"affected", value:"Apple Safari versions prior to 5.1");

  script_tag(name:"insight", value:"Please see the references for more details about the vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.1 or later.");

  script_tag(name:"summary", value:"Apple Safari web browser is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"5.34.50.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 5.1 (5.34.50.0)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
