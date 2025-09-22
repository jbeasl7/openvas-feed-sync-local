# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806868");
  script_version("2023-09-15T16:10:33+0000");
  script_tag(name:"last_modification", value:"2023-09-15 16:10:33 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2016-02-15 12:26:35 +0530 (Mon, 15 Feb 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_date", value:"2016-12-06 03:05:00 +0000 (Tue, 06 Dec 2016)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");

  script_cve_id("CVE-2016-0950", "CVE-2016-0949", "CVE-2016-0948");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe Connect < 9.5.2 Multiple Vulnerabilities (APSB16-07)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_http_detect.nasl");
  script_mandatory_keys("adobe/connect/detected");

  script_tag(name:"summary", value:"Adobe Connect is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - An insufficient input validation in a URL parameter.

  - A vulnerability that could be used to misrepresent information presented in the user interface.

  - Cross-Site Request Forgery (CSRF).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to spoof the
  user interface, to hijack the authentication of unspecified victims and an unspecified impact.");

  script_tag(name:"affected", value:"Adobe Connect prior to version 9.5.2.");

  script_tag(name:"solution", value:"Update to version 9.5.2 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb16-07.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83122");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83115");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "9.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
