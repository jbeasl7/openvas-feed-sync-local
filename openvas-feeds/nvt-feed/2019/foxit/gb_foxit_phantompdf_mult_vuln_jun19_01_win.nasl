# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815227");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2019-6752", "CVE-2019-6756", "CVE-2019-6762", "CVE-2019-6765");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-12 17:49:00 +0000 (Wed, 12 Oct 2022)");
  script_tag(name:"creation_date", value:"2019-06-28 12:38:44 +0530 (Fri, 28 Jun 2019)");
  script_name("Foxit PhantomPDF < 8.3.10, 9.x < 9.5 Multiple Vulnerabilities (Jun 2019) - Windows");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An issue in conversion of HTML files to PDF resulting from lack of proper validation
    of user-supplied data, which can result in a read past the end of an allocated object.

  - An issue in the parsing of HTML files which results from lack of validating the existence
    of an object prior to performing operations on the object.

  - An issue in the parsing of PDF documents resulting from lack of proper validation of
    user-supplied data, which can result in a read past the end of an allocated object.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to disclose sensitive information and execute arbitrary code.");

  script_tag(name:"affected", value:"Foxit PhantomPDF versions 8.3.9.41099 and prior
  and 9.x to  9.4.1.16828  on Windows.");

  script_tag(name:"solution", value:"Update to version 8.3.10, 9.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pdfVer = infos["version"];
pdfPath = infos["location"];

if(version_is_less_equal(version:pdfVer, test_version:"8.3.9.41099")){
  vulnerable_range =  "8.3.10";
}

else if(version_in_range(version:pdfVer, test_version:"9.0", test_version2:"9.4.1.16828")){
   vulnerable_range =  "9.5";
}

if(vulnerable_range)
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:vulnerable_range, install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(99);
