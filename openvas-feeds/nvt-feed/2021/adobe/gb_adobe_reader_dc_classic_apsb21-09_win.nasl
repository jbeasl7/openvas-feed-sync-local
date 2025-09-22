# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817927");
  script_version("2023-10-20T16:09:12+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-21046", "CVE-2021-21017", "CVE-2021-21037", "CVE-2021-21036",
                "CVE-2021-21045", "CVE-2021-21042", "CVE-2021-21034", "CVE-2021-21061",
                "CVE-2021-21044", "CVE-2021-21038", "CVE-2021-21058", "CVE-2021-21059",
                "CVE-2021-21062", "CVE-2021-21063", "CVE-2021-21057", "CVE-2021-21060",
                "CVE-2021-21041", "CVE-2021-21040", "CVE-2021-21039", "CVE-2021-21035",
                "CVE-2021-21033", "CVE-2021-21028", "CVE-2021-21021", "CVE-2021-28545",
                "CVE-2021-28546", "CVE-2021-21086", "CVE-2021-21089", "CVE-2021-40723",
                "CVE-2021-21088");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 18:15:00 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-02-11 10:38:28 +0530 (Thu, 11 Feb 2021)");
  script_name("Adobe Reader Classic 2020 Security Update (APSB21-09) - Windows");

  script_tag(name:"summary", value:"Adobe Reader Classic 2020 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple buffer overflow errors.

  - Multiple use-after-free errors.

  - Multiple out-of-bounds read/write errors.

  - An integer overflow error.

  - A path traversal error.

  - A NULL pointer dereference error.

  - An input validation error.

  - Missing Support for Integrity Check.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, diclose sensitive information, escalate privileges,
  bypass security restrictions and cause denial-of-service.");

  script_tag(name:"affected", value:"Adobe Reader Classic 2020 prior to version
  2020.001.30020 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader Classic 2020 to
  version 2020.001.30020 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-09.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_reader_dc_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/ReaderDC/Classic/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"20.0", test_version2:"20.001.30018")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"20.001.30020(2020.001.30020)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
