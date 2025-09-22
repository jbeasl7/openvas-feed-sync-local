# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802747");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2012-0777", "CVE-2012-0776", "CVE-2012-0774", "CVE-2012-0775");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-04-16 19:08:36 +0530 (Mon, 16 Apr 2012)");
  script_name("Adobe Reader Multiple Vulnerabilities (Apr 2012) - Linux");


  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaws are due to

  - An unspecified error when handling JavaScript/JavaScript API can be exploited
to corrupt memory.

  - An integer overflow error when handling True Type Font (TTF) can be exploited
to corrupt memory.

  - The application loads executables (msiexec.exe) in an insecure manner.");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to bypass certain security restrictions,
execute arbitrary code via unspecified vectors or cause a denial of service.");
  script_tag(name:"affected", value:"Adobe Reader version 9.x to 9.4.6 on Linux");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 9.5.1 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48733/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52949");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52950");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52951");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52952");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026908");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-08.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
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
  if(version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.4.6")){
    report = report_fixed_ver(installed_version:readerVer, vulnerable_range:"9.0 - 9.4.6");
    security_message(port:0, data:report);
  }
}
