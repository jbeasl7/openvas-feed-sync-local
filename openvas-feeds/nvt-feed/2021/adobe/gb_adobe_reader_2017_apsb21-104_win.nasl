# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818814");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2021-40728", "CVE-2021-40729", "CVE-2021-40730", "CVE-2021-40731");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-15 15:15:09 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-14 15:31:53 +0530 (Thu, 14 Oct 2021)");
  script_name("Adobe Reader 2017 Security Update (APSB21-104) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat Reader is prone to multiple
  code execution and privilege escalation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use-after-free errors.

  - An out-of-bounds read error.

  - An out-of-bounds write error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and escalate privileges on a vulnerable system.");

  script_tag(name:"affected", value:"Adobe Reader 2017 version prior to
  2017.011.30204 on Windows.");

  script_tag(name:"solution", value:"Update Adobe Reader 2017 to version
  2017.011.30204 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-104.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.011.30202")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.011.30204(2017.011.30204)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
