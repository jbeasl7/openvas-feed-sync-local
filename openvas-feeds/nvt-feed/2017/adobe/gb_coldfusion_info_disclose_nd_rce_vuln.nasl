# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:coldfusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811696");
  script_version("2025-01-15T05:38:11+0000");
  script_cve_id("CVE-2017-11286", "CVE-2017-11285", "CVE-2017-11283", "CVE-2017-11284");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-15 05:38:11 +0000 (Wed, 15 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-04 14:09:00 +0000 (Fri, 04 Sep 2020)");
  script_tag(name:"creation_date", value:"2017-09-14 15:04:23 +0530 (Thu, 14 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe ColdFusion Multiple Vulnerabilities (APSB17-30)");

  script_tag(name:"summary", value:"Adobe ColdFusion is prone to information disclosure and remote
  code execution (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-11286: Improper Restriction of XML External Entity Reference

  - CVE-2017-11285: mproper Neutralization of Input During Web Page Generation

  - CVE-2017-11283, CVE-2017-11284: Deserialization of Untrusted Data");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the affected application
  and gain access to sensitive information.");

  script_tag(name:"affected", value:"- Adobe ColdFusion 11 prior to update 13

  - Adobe ColdFusion 2016 prior to update 5");

  script_tag(name:"solution", value:"Update to Adobe ColdFusion 11 update 13, 2016 update 5 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb17-30.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100715");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100711");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100708");
  script_xref(name:"URL", value:"https://www.hoyahaxa.com/2023/09/exploiting-cve-2017-11286.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

#https://helpx.adobe.com/coldfusion/kb/coldfusion-11-update-13.html
if(version_in_range(version:version, test_version:"11.0", test_version2:"11.0.13.303667")) {
  fix = "11.0.13.303668";
}

#https://helpx.adobe.com/coldfusion/kb/coldfusion-2016-update-5.html
else if(version_in_range(version:version, test_version:"2016.0", test_version2:"2016.0.05.303688")) {
  fix = "2016.0.05.303689";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
