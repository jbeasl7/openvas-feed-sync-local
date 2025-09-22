# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813196");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2017-17557", "CVE-2017-14458", "CVE-2018-3842", "CVE-2018-3853",
                "CVE-2018-3850", "CVE-2018-10303", "CVE-2018-10302", "CVE-2018-3843");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-03 14:19:00 +0000 (Sat, 03 Dec 2022)");
  script_tag(name:"creation_date", value:"2018-05-18 12:43:57 +0530 (Fri, 18 May 2018)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities (May 2018) - Windows");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An unsafe DLL loading as application passes an insufficiently qualified path
    in loading an external library when a user launches the application.

  - An out-of-bounds read and write error.

  - A type confusion error while executing certain XFA functions in crafted PDF
    files since the application could transform non-CXFA_Object to CXFA_Object
    without judging the data type and use the discrepant CXFA_Object to get layout
    object directly.

  - An unspecified error in GoToE & GoToR Actions.

  - The application is not running in Safe-Reading-Mode and can be abused via
    '_JP2_Codestream_Read_SOT' function.

  - An error as application do not handle a COM object properly.

  - A use-after-free error as the application could continue to traverse pages
    after the document has been closed or free certain objects repeatedly.

  - Uninitialized memory or pointer error due to the use of uninitialized new
    'Uint32Array' object or member variables in 'PrintParams' or 'm_pCurContex'
    objects.

  - A use-after-free error due to the use of freed object when executing JavaScript
    or invoking certain functions to get object properties.

  - A use-after-free error due to the use of object which has been closed or removed.

  - A type confusion error when parsing files with associated file annotations due
    to deference of an object of invalid type.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service condition, execute arbitrary code and
  gain access to sensitive data from memory.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version 8.3.5.30351 and
  earlier on windows");

  script_tag(name:"solution", value:"Upgrade to Foxit PhantomPDF version 8.3.6
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php#content-2018");

  script_copyright("Copyright (C) 2018 Greenbone AG");
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

## 8.3.6 == 8.3.6.35572
if(version_is_less(version:pdfVer, test_version:"8.3.6.35572"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"8.3.6", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(0);
