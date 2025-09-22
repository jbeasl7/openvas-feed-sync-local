# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817251");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2020-9669", "CVE-2020-9671", "CVE-2020-9670", "CVE-2020-9682");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-22 20:23:00 +0000 (Wed, 22 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-27 12:34:15 +0530 (Mon, 27 Jul 2020)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Creative Cloud Security Update (APSB20-33) - Windows");

  script_tag(name:"summary", value:"Adobe Creative cloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An insecure file permissions vulnerability error.

  - Multiple symlink errors.

  - Lack of Exploit Mitigations.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to arbitrary file system write and escalate privileges on the target system.");

  script_tag(name:"affected", value:"Adobe Creative Cloud 5.1 and earlier versions.");

  script_tag(name:"solution", value:"Update to Adobe Creative Cloud version 5.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb20-33.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_win.nasl");
  script_mandatory_keys("AdobeCreativeCloud/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"5.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.2", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
