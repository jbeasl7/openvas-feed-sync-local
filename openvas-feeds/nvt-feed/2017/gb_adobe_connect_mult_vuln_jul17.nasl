# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811480");
  script_version("2023-09-15T16:10:33+0000");
  script_tag(name:"last_modification", value:"2023-09-15 16:10:33 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2017-07-13 12:18:52 +0530 (Thu, 13 Jul 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-3101", "CVE-2017-3102", "CVE-2017-3103");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Adobe Connect Multiple Vulnerabilities (APSB17-22)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_http_detect.nasl");
  script_mandatory_keys("adobe/connect/detected");

  script_tag(name:"summary", value:"Adobe Connect is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - User Interface (UI) Misrepresentation of Critical Information.

  - Improper Neutralization of Input During Web Page Generation.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  reflected and stored cross-site scripting attacks, UI redressing (or clickjacking) attacks.");

  script_tag(name:"affected", value:"Adobe Connect prior to 9.6.2.");

  script_tag(name:"solution", value:"Update to version 9.6.2 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/connect/apsb17-22.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99521");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99517");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99518");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "9.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.6.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
