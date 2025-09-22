# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804629");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2002-1764");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-06-05 12:20:17 +0530 (Thu, 05 Jun 2014)");
  script_name("Adobe Reader Temporary Files Arbitrary File Overwrite Vulnerability - Linux");

  script_tag(name:"summary", value:"Adobe Reader is prone to symlink attack vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to the creation of insecure temporary files when opening or
printing PDF files");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to create a symbolic link from a
file in the /tmp directory to an arbitrary file on the system so that the
arbitrary file is overwritten once the PDF file is opened.");
  script_tag(name:"affected", value:"Adobe Reader version 4.0.5 on Linux.");
  script_tag(name:"solution", value:"Update to Adobe Reader version 5.0.5 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/9407");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5068");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(readerVer  =~ "^4\.")
{
  if(version_is_equal(version:readerVer, test_version:"4.0.5"))
  {
    report = report_fixed_ver(installed_version:readerVer, vulnerable_range:"Equal to 4.0.5");
    security_message(port:0, data:report);
    exit(0);
  }
}
