# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:honeywell:xl_web_ii_controller";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106561");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-02-03 09:38:09 +0700 (Fri, 03 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-5139", "CVE-2017-5140", "CVE-2017-5141", "CVE-2017-5142", "CVE-2017-5143");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Honeywell XL Web Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_honeywell_xlweb_consolidation.nasl");
  script_mandatory_keys("honeywell/excel_web/detected");

  script_tag(name:"summary", value:"Honeywell XL Web is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Honeywell XL Web is prone to multiple vulnerabilities:

  - Any user is able to disclose a password by accessing a specific URL. (CVE-2017-5139)

  - Password is stored in clear text (CVE-2017-5140)

  - An attacker can establish a new user session, without invalidating any existing session identifier, which gives
the opportunity to steal authenticated sessions. (CVE-2017-5141)

  - A user with low privileges is able to open and change the parameters by accessing a specific URL.
(CVE-2017-5142)

  - A user without authenticating can make a directory traversal attack by accessing a specific URL.
(CVE-2017-5143)");

  script_tag(name:"impact", value:"An unauthenticated attacker may obtain a password and take complete control
over the device.");

  script_tag(name:"affected", value:"XL1000C500 XLWebExe-2-01-00 and prior and XLWeb 500 XLWebExe-1-02-08 and
prior.");

  script_tag(name:"solution", value:"Users are encouraged to contact the local Honeywell HBS branch to have
their sites updated to the latest version.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-033-01");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.02.08")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Please contact the vendor.");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.00.00", test_version2: "2.01.00")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Please contact the vendor.");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
