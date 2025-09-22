# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nuance:pdf_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804360");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2013-0732");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-04-04 13:11:15 +0530 (Fri, 04 Apr 2014)");
  script_name("Nuance PDF Reader 'pdfcore8.dll' Buffer Overflow Vulnerability (Apr 2014)");

  script_tag(name:"summary", value:"Nuance PDF Reader is prone to a buffer overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to an error in 'pdfcore8.dll' when processing naming table
entries within embedded TTF files.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct denial of
service or possibly execution of arbitrary code.");
  script_tag(name:"affected", value:"Nuance PDF Reader version before 8.1");
  script_tag(name:"solution", value:"Upgrade to Nuance PDF Reader version 8.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51943");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60315");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/84695");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_dependencies("gb_nuance_pdf_reader_detect_win.nasl");
  script_mandatory_keys("Nuance/PDFReader/Win/Ver");
  script_xref(name:"URL", value:"http://www.nuance.com/products/pdf-reader/index.htm");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!nuaVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:nuaVer, test_version:"8.10.1302"))
{
  report = report_fixed_ver(installed_version:nuaVer, fixed_version:"8.10.1302");
  security_message(port:0, data:report);
  exit(0);
}
