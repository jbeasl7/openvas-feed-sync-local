# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815229");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2018-17625", "CVE-2018-17626", "CVE-2018-17627", "CVE-2018-17628",
                "CVE-2018-17629", "CVE-2018-17630", "CVE-2018-17631", "CVE-2018-17632",
                "CVE-2018-17633", "CVE-2018-17634", "CVE-2018-17635", "CVE-2018-17636",
                "CVE-2018-17637", "CVE-2018-17638", "CVE-2018-17639", "CVE-2018-17640",
                "CVE-2018-17641", "CVE-2018-17642", "CVE-2018-17643", "CVE-2018-17644",
                "CVE-2018-17645", "CVE-2018-17646", "CVE-2018-17647", "CVE-2018-17648",
                "CVE-2018-17649", "CVE-2018-17650", "CVE-2018-17651", "CVE-2018-17652",
                "CVE-2018-17653", "CVE-2018-17654", "CVE-2018-17655", "CVE-2018-17656",
                "CVE-2018-17657", "CVE-2018-17658", "CVE-2018-17659", "CVE-2018-17660",
                "CVE-2018-17661", "CVE-2018-17662", "CVE-2018-17663", "CVE-2018-17664",
                "CVE-2018-17665", "CVE-2018-17666", "CVE-2018-17667", "CVE-2018-17668",
                "CVE-2018-17669", "CVE-2018-17670", "CVE-2018-17671", "CVE-2018-17672",
                "CVE-2018-17673", "CVE-2018-17674", "CVE-2018-17675", "CVE-2018-17676",
                "CVE-2018-17677", "CVE-2018-17678", "CVE-2018-17679", "CVE-2018-17680",
                "CVE-2018-17681", "CVE-2018-17682", "CVE-2018-17683", "CVE-2018-17684",
                "CVE-2018-17685", "CVE-2018-17686", "CVE-2018-17696", "CVE-2018-17697",
                "CVE-2018-17699", "CVE-2018-17702", "CVE-2018-17703", "CVE-2018-17704",
                "CVE-2018-17705");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:36:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-06-28 14:55:15 +0530 (Fri, 28 Jun 2019)");
  script_name("Foxit Reader < 9.3 Multiple Vulnerabilities (Jun 2019) - Windows");

  script_tag(name:"summary", value:"Foxit Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An issue in handling of the setInterval() method resulting from lack of
    validating the existence of an object prior to performing operations on the object.

  - An issue in handling of the Validate events of TextBox objects resulting from
    lack of validating the existence of an object prior to performing operations
    on the object.

  - An issue in handling of the XFA mouseUp event resulting from lack of validating
    the existence of an object prior to performing operations on the object.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Foxit Reader version 9.2.0.9297 and earlier on Windows.");

  script_tag(name:"solution", value:"Update to version 9.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_mandatory_keys("foxit/reader/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

pdfVer = infos["version"];
pdfPath = infos["location"];

if(version_is_less_equal(version:pdfVer, test_version:"9.2.0.9297")) {
  report = report_fixed_ver(installed_version:pdfVer, fixed_version:"9.3", install_path:pdfPath);
  security_message(data:report);
  exit(0);
}

exit(99);
