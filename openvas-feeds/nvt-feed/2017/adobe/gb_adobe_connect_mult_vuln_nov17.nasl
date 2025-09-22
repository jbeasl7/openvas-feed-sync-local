# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812212");
  script_version("2023-09-15T16:10:33+0000");
  script_tag(name:"last_modification", value:"2023-09-15 16:10:33 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2017-11-16 12:45:11 +0530 (Thu, 16 Nov 2017)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-14 14:57:00 +0000 (Thu, 14 Dec 2017)");

  script_cve_id("CVE-2017-11291", "CVE-2017-11287", "CVE-2017-11288", "CVE-2017-11289",
                "CVE-2017-11290");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe Connect Multiple Vulnerabilities (APSB17-35)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_http_detect.nasl");
  script_mandatory_keys("adobe/connect/detected");

  script_tag(name:"summary", value:"Adobe Connect is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple input validation errors.

  - A critical Server-Side Request Forgery error.

  - An UI redressing error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass
  network access controls, execute arbitrary script code in the browser of an unsuspecting user in
  the context of the affected site and conduct clickjacking attacks.");

  script_tag(name:"affected", value:"Adobe Connect version 9.6.2 and prior.");

  script_tag(name:"solution", value:"Update to version 9.7 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb17-35.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101838");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "9.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
