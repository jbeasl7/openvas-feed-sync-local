# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:tivoli_endpoint_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809886");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2016-0296", "CVE-2016-0297", "CVE-2016-0396", "CVE-2016-0214");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-07 19:44:00 +0000 (Tue, 07 Feb 2017)");
  script_tag(name:"creation_date", value:"2017-02-16 11:44:50 +0530 (Thu, 16 Feb 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Tivoli Endpoint Manager Multiple Vulnerabilities (Feb 2017)");

  script_tag(name:"summary", value:"IBM Tivoli Endpoint Manager is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - Enabling relay authentication(By default, unrestricted file upload on
    relays/servers with relay authentication is disabled).

  - Storage of potentially sensitive information in log files that could be
    available to a local user.

  - A missing HTTP Strict-Transport-Security Header through mitm.

  - An input validation error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to upload a malicious file, to obtain sensitive information, also to
  inject commands that would be executed with unnecessary higher privileges than
  expected.");

  script_tag(name:"affected", value:"IBM Tivoli Endpoint Manager versions
  9.0, 9.1, 9.2, 9.5");

  script_tag(name:"solution", value:"Apply the fixes from the referenced links.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21993203");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94213");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94188");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94193");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94155");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21993213");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21993214");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21993206");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_endpoint_manager_web_detect.nasl");
  script_mandatory_keys("ibm_endpoint_manager/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!tivPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!tivVer = get_app_version(cpe:CPE, port:tivPort)){
  exit(0);
}

if (version_is_less(version: tivVer, test_version: "9.1.1275.0")) {
  report = report_fixed_ver(installed_version: tivVer, fixed_version: "9.1.1275.0");
  security_message(port: tivPort, data: report);
  exit(0);
}

if (tivVer =~ "^9\.2\.") {
  if (version_is_less(version: tivVer, test_version: "9.2.8.74")) {
    report = report_fixed_ver(installed_version: tivVer, fixed_version: "9.2.8.74");
    security_message(port: tivPort, data: report);
    exit(0);
  }
}

if (tivVer =~ "^9\.5\.") {
  if (version_is_less(version: tivVer, test_version: "9.5.3.211")) {
    report = report_fixed_ver(installed_version: tivVer, fixed_version: "9.5.3.211");
    security_message(port: tivPort, data: report);
    exit(0);
  }
}

exit(99);
