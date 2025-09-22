# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:foxit_pdf_toolkit";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810521");
  script_version("2025-03-04T05:38:25+0000");
  script_cve_id("CVE-2017-5364");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-03 02:59:00 +0000 (Fri, 03 Feb 2017)");
  script_tag(name:"creation_date", value:"2017-01-25 15:52:27 +0530 (Wed, 25 Jan 2017)");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("Foxit PDF Toolkit PDF File Parsing Memory Corruption Vulnerability");

  script_tag(name:"summary", value:"Foxit PDF Toolkit is prone to a memory corruption
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a memory corruption vulnerability in Foxit
  PDF Toolkit while parsing PDF files.");

  script_tag(name:"impact", value:"Successful exploitation will allow allow an attacker to cause
  denial of Service and remote code execution when the victim opens the specially crafted PDF
  file.");

  script_tag(name:"affected", value:"Foxit PDF Toolkit version 1.3.");

  script_tag(name:"solution", value:"Update to version 2.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_pdf_toolkit_smb_login_detect.nasl");
  script_mandatory_keys("foxit/pdf_toolkit/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE))
  exit(0);

if(version_is_equal(version:version, test_version:"1.3"))
{
  report = report_fixed_ver(installed_version:version, fixed_version: "2.0");
  security_message(data:report );
  exit(0);
}

exit(0);
