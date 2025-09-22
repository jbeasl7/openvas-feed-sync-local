# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807556");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2016-4059", "CVE-2016-4060", "CVE-2016-4061", "CVE-2016-4062",
                "CVE-2016-4063", "CVE-2016-4064", "CVE-2016-4065");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 20:14:00 +0000 (Mon, 28 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-04-25 16:44:43 +0530 (Mon, 25 Apr 2016)");
  script_name("Foxit Reader Multiple RCE Vulnerabilities");

  script_tag(name:"summary", value:"Foxit Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The multiple Use-after-free vulnerabilities.

  - The error in parsing malformed content stream.

  - The application recursively called the format error of some PDFs and led to
    no response when opening the PDF.

  - The destructor of the object whose generation number is -1 in the PDF file
    could release the file handle which had been imported by the application
    layer.

  - The error in decoding corrupted images during PDF conversion with the gflags
    app enabled.

  - The XFA's underlying data failed to synchronize with that of
    PhantomPDF/Reader caused by the re-layout underlying XFA.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (application crash).");

  script_tag(name:"affected", value:"Foxit Reader version 7.3.0.118 and
  earlier.");

  script_tag(name:"solution", value:"Upgrade to Foxit Reader version
  7.3.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-219");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-221");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2016 Greenbone AG");
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

## Foxit Reader version 7.3.4 = 7.3.4.311
if(version_is_less_equal(version:foxitVer, test_version:"7.3.0.118"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"7.3.4.311");
  security_message(data:report);
  exit(0);
}
