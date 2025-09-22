# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:checkmk:checkmk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146390");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-07-28 09:35:32 +0000 (Wed, 28 Jul 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-05 14:06:00 +0000 (Thu, 05 Aug 2021)");

  script_cve_id("CVE-2021-36563");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Check MK < 1.6.0p25, 2.0.x < 2.0.0p4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_checkmk_server_http_detect.nasl");
  script_mandatory_keys("checkmk/server/detected");

  script_tag(name:"summary", value:"Check MK is prone to a cross-site scripting (XSS) vulnerability
  in the management web console.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The CheckMK management web console does not sanitise user input
  in various parameters of the WATO module. This allows an attacker to open a backdoor on the
  device with HTML content and interpreted by the browser (such as JavaScript or other client-side
  scripts), the XSS payload will be triggered when the user accesses some specific sections of the
  application. In the same sense a very dangerous potential way would be when an attacker who has
  the monitor role (not administrator) manages to get a stored XSS to steal the secretAutomation
  (for the use of the API in administrator mode) and thus be able to create another administrator
  user who has high privileges on the CheckMK monitoring web console. Another way is that
  persistent XSS allows an attacker to modify the displayed content or change the victim's
  information. Successful exploitation requires access to the web management interface, either with
  valid credentials or with a hijacked session.");

  script_tag(name:"affected", value:"Check MK version 1.6.0p24 and prior and 2.0.x through
  2.0.0p3.");

  script_tag(name:"solution", value:"Update to version 1.6.0p25, 2.0.0p4 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/werk/12762");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.6.0p24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.0p25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.0.0", test_version2: "2.0.0p3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.0.0p4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
