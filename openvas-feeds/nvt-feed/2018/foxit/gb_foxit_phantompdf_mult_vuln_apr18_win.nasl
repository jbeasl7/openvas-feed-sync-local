# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813157");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2018-3842", "CVE-2017-17557", "CVE-2017-14458", "CVE-2018-3853",
                "CVE-2018-3850", "CVE-2018-3843", "CVE-2018-10302");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-04 01:12:00 +0000 (Sat, 04 Feb 2023)");
  script_tag(name:"creation_date", value:"2018-04-25 14:50:06 +0530 (Wed, 25 Apr 2018)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities (Apr 2018) - Windows");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error where the application passes an insufficiently qualified path in
    loading an external library when a user launches the application.

  - A heap buffer overflow error.

  - Multiple use-after-free errors.

  - The use of uninitialized new 'Uint32Array' object or member variables in
    'PrintParams' or 'm_pCurContex' objects.

  - An incorrect memory allocation, memory commit, memory access, or array access.

  - Type Confusion errors.

  - An error in 'GoToE' & 'GoToR' Actions.

  - An out-of-bounds read error in the '_JP2_Codestream_Read_SOT' function.

  - An error since the application did not handle a COM object properly.

  - An error allowing users to embed executable files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service condition, execute arbitrary code and
  gain access to sensitive data from memory.");

  script_tag(name:"affected", value:"Foxit PhantomPDF versions 9.0.1.1049 and
  prior on windows");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version 9.1 or later. Please see the references for more information.");

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

## 9.1 == 9.1.0.5096
if(version_is_less(version:pdfVer, test_version:"9.1.0.5096"))
{
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"9.1", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}
exit(0);
