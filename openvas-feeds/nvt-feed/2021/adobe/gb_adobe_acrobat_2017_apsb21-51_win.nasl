# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818196");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2021-35988", "CVE-2021-35987", "CVE-2021-35980", "CVE-2021-28644",
                "CVE-2021-28640", "CVE-2021-28643", "CVE-2021-28641", "CVE-2021-28639",
                "CVE-2021-28642", "CVE-2021-28637", "CVE-2021-35986", "CVE-2021-28638",
                "CVE-2021-35985", "CVE-2021-35984", "CVE-2021-28636", "CVE-2021-28634",
                "CVE-2021-35983", "CVE-2021-35981", "CVE-2021-28635");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-31 16:59:00 +0000 (Tue, 31 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-12 13:09:23 +0530 (Thu, 12 Aug 2021)");
  script_name("Adobe Acrobat 2017 Security Update (APSB21-51) - Windows");

  script_tag(name:"summary", value:"The host is missing an important security
  update according to Adobe August update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use-after-free errors.

  - Multiple out-of-bounds read errors.

  - Multiple out-of-bounds write errors.

  - A type confusion error.

  - A heap-based buffer overflow error.

  - Multiple null pointer dereference errors.

  - An input validation error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, read arbitrary files and disclose sensitive
  information on vulnerable system.");

  script_tag(name:"affected", value:"Adobe Acrobat 2017 version prior to
  2017.011.30199 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat 2017 version
  2017.011.30199 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-51.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.011.30197")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.011.30199(2017.011.30199)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
