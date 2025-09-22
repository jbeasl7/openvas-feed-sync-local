# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814687");
  script_version("2025-01-15T05:38:11+0000");
  script_cve_id("CVE-2019-7091", "CVE-2019-7092");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-15 05:38:11 +0000 (Wed, 15 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-04 14:21:00 +0000 (Fri, 04 Sep 2020)");
  script_tag(name:"creation_date", value:"2019-02-14 12:03:46 +0530 (Thu, 14 Feb 2019)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion Multiple Vulnerabilities (APSB19-10)");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to code execution and
  information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an improper validation
  and deserialization of untrusted data.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the affected application
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Adobe ColdFusion version 11 before Update 16.");

  script_tag(name:"solution", value:"Upgrade to Adobe ColdFusion 11 Update 16 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb19-10.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
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

if(version_in_range(version:version, test_version:"11.0", test_version2:"11.0.15.307976")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"ColdFusion 11 Update 16", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
