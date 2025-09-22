# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802167");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2011-2431", "CVE-2011-2432", "CVE-2011-2433", "CVE-2011-2434",
                "CVE-2011-2435", "CVE-2011-2436", "CVE-2011-2437", "CVE-2011-2438",
                "CVE-2011-2439", "CVE-2011-2440", "CVE-2011-2441", "CVE-2011-2442");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)");
  script_name("Adobe Reader Multiple Vulnerabilities (Sep 2011) - Linux");


  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to memory corruptions, and buffer overflow errors.");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code via
unspecified vectors.");
  script_tag(name:"affected", value:"Adobe Reader version 9.x through 9.4.5");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.4.6 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-24.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49572");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49575");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49576");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49577");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49579");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49580");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49581");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49582");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49583");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49584");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49585");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");


if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer =~ "^9")
{
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.5"))
  {
    report = report_fixed_ver(installed_version:readerVer, vulnerable_range:"9.0 - 9.4.5");
    security_message(port: 0, data: report);
    exit(0);
  }
}
