# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814322");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2018-18933", "CVE-2018-19347", "CVE-2018-19348", "CVE-2018-19346",
                "CVE-2018-19345", "CVE-2018-19343", "CVE-2018-19344", "CVE-2018-19341",
                "CVE-2018-19342", "CVE-2018-19390", "CVE-2018-19389", "CVE-2018-19388");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-30 19:23:00 +0000 (Wed, 30 Jan 2019)");
  script_tag(name:"creation_date", value:"2018-11-07 11:55:44 +0530 (Wed, 07 Nov 2018)");

  script_name("Foxit Reader U3D Plugin Multiple Vulnerabilities (Nov 2018) - Windows");

  script_tag(name:"summary", value:"Foxit Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists because the parsing of a u3d
  sample by Foxit Reader causes an out-of-bounds memory access");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service or obtain sensitive information via
  a U3D sample");

  script_tag(name:"affected", value:"Foxit Reader 9.3.0.10826 on Windows.");

  script_tag(name:"solution", value:"See the vendor advisory for a solution.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105587");
  script_xref(name:"URL", value:"https://yan-1-20.github.io/2018/11/02/2018/11/2018-11-02/");

  script_copyright("Copyright (C) 2018 Greenbone AG");
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

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"9.3.0.10826")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
