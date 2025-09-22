# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807588");
  script_version("2025-01-15T05:38:11+0000");
  script_cve_id("CVE-2016-1113", "CVE-2016-1114", "CVE-2016-1115");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-15 05:38:11 +0000 (Wed, 15 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-04 14:05:00 +0000 (Fri, 04 Sep 2020)");
  script_tag(name:"creation_date", value:"2016-05-16 13:44:30 +0530 (Mon, 16 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion Multiple Vulnerabilities (APSB16-16)");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An insufficient validation of user supplied input via unspecified vectors.

  - An important Java deserialization vulnerability in
    Apache Commons Collections library.

  - The mishandling of wildcards in name fields of X.509 certificates.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via unspecified vectors
  and allow man-in-the-middle attackers to spoof servers.");

  script_tag(name:"affected", value:"ColdFusion 10 before Update 19 and
  11 before Update 8.");

  script_tag(name:"solution", value:"Upgrade to version 10 Update 19 or
  11 Update 8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb16-16.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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
location = infos["location"];

if(version_in_range(version:version, test_version:"10.0", test_version2:"10.0.19.298510")) {
  fix = "10.0.19.298511";
}

else if(version_in_range(version:version, test_version:"11.0", test_version2:"11.0.08.298511")) {
  fix = "11.0.08.298512";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
