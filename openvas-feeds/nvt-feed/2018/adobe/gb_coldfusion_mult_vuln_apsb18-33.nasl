# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813925");
  script_version("2025-01-15T05:38:11+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-15965", "CVE-2018-15957", "CVE-2018-15958", "CVE-2018-15959",
                "CVE-2018-15964", "CVE-2018-15963", "CVE-2018-15962", "CVE-2018-15961",
                "CVE-2018-15960");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-15 05:38:11 +0000 (Wed, 15 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-04 14:09:00 +0000 (Fri, 04 Sep 2020)");
  script_tag(name:"creation_date", value:"2018-09-12 12:38:39 +0530 (Wed, 12 Sep 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion Multiple Vulnerabilities (APSB18-33)");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error while deserialization of untrusted data.

  - Use of a component with a known vulnerability.

  - A security bypass vulnerability.

  - Unauthorized access to directory listing.

  - Unrestricted file upload.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, disclose information, create arbitrary
  page and overwrite arbitrary file.");

  script_tag(name:"affected", value:"Adobe ColdFusion 2018 (July 12 release),
  ColdFusion 2016 update 6 and earlier, ColdFusion 11 Update 14 and earlier.");

  script_tag(name:"solution", value:"Upgrade Adobe ColdFusion to ColdFusion 2018
  Update 1 or ColdFusion 2016 Update 7 or ColdFusion 11 Update 15 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb18-33.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_coldfusion_http_detect.nasl");
  script_mandatory_keys("adobe/coldfusion/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+")) # nb: The HTTP Detection VT might only extract the major version like 11 or 2021
  exit(0);

version = infos["version"];
path = infos["location"];

## https://helpx.adobe.com/coldfusion/kb/coldfusion-11-update-15.html
if(version_in_range(version:version, test_version:"11.0", test_version2:"11.0.15.311398")){
  fix = "11.0.15.311399";
}

## https://helpx.adobe.com/coldfusion/kb/coldfusion-2016-update-7.html
if(version_in_range(version:version, test_version:"2016.0", test_version2:"2016.0.07.311391")){
  fix = "2016.0.07.311392";
}

## https://helpx.adobe.com/coldfusion/kb/coldfusion-2018-update-1.html
if(version_in_range(version:version, test_version:"2018.0", test_version2:"2018.0.01.311401")){
  fix = "2018.0.01.311402";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
