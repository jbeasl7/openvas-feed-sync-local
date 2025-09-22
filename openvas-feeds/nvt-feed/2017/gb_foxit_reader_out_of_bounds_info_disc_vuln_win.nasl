# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807395");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-8334");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-11 02:59:00 +0000 (Wed, 11 Jan 2017)");
  script_tag(name:"creation_date", value:"2017-01-17 16:07:07 +0530 (Tue, 17 Jan 2017)");
  script_name("Foxit Reader Out of Bounds Read Local Information Disclosure Vulnerability - Windows");

  script_tag(name:"summary", value:"Foxit Reader is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A large out of bounds read on the heap
  vulnerability in Foxit PDF Reader can potentially be abused for information
  disclosure. Combined with another vulnerability, it can be used to leak heap
  memory layout and in bypassing ASLR.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to obtain sensitive information that may aid in launching further
  attacks.");

  script_tag(name:"affected", value:"Foxit Reader version 8.0.2.805 on Windows");
  script_tag(name:"solution", value:"Upgrade to Foxit Reader 8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93799");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0201");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!foxitVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(foxitVer == "8.0.2.805")
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"8.1");
  security_message(data:report);
  exit(0);
}
