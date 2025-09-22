# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834798");
  script_version("2024-12-06T05:05:38+0000");
  script_cve_id("CVE-2022-24954", "CVE-2021-44709", "CVE-2021-44740", "CVE-2021-44741",
                "CVE-2021-44708", "CVE-2022-25108", "CVE-2022-24955", "CVE-2022-24359",
                "CVE-2022-24358", "CVE-2022-24357", "CVE-2022-24360", "CVE-2022-24363",
                "CVE-2022-24362", "CVE-2021-40420", "CVE-2022-24364", "CVE-2022-24365",
                "CVE-2022-24366", "CVE-2022-24367", "CVE-2022-24368", "CVE-2022-24361",
                "CVE-2022-24971", "CVE-2022-24369", "CVE-2022-24907", "CVE-2022-24908",
                "CVE-2022-22150", "CVE-2018-1285", "CVE-2021-40729");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-06 05:05:38 +0000 (Fri, 06 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-17 03:22:59 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2024-12-04 14:41:50 +0530 (Wed, 04 Dec 2024)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities (Dec 2024) - Windows");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to execute remote code, escalate privileges, disclose information and conduct
  denial of service attacks.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version 11.x through
  11.2.0.53415, 10.1.6.37749 and prior on Windows.");

  script_tag(name:"solution", value:"Update to version 10.1.7 or 11.2.1 or
  13.1.4 or 2024.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"10.1.6.37749")) {
  fix = "10.1.7";
}

if(version_in_range(version:vers, test_version:"11.0", test_version2:"11.2.0.53415")) {
  fix = "11.2.1";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);

