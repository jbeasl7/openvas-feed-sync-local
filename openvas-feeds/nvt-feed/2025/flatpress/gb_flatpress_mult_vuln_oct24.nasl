# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:flatpress:flatpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128155");
  script_version("2025-08-05T05:45:17+0000");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-06-13 09:02:25 +0000 (Fri, 13 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-16 13:33:21 +0000 (Wed, 16 Oct 2024)");

  script_cve_id("CVE-2024-31835", "CVE-2024-33209", "CVE-2024-33210");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("FlatPress <= 1.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_flatpress_http_detect.nasl");
  script_mandatory_keys("flatpress/detected");

  script_tag(name:"summary", value:"FlatPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-31835: A Cross Site Scripting (XSS) vulnerability in flatpress CMS Flatpress v1.3
  allows a remote attacker to execute arbitrary code via a craftedpayload to the file name
  parameter.

  - CVE-2024-33209: An attacker can inject malicious JavaScript code into the 'Add New Entry'
  section, which allows them to execute arbitrary code in the context of a victim's web browser.

  - CVE-2024-33210: A cross-site scripting (XSS) vulnerability allows an attacker to inject
  malicious scripts into web pages viewed by other users.");

  script_tag(name:"affected", value:"FlatPress version 1.3 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 20th June, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/paragbagul111/CVE-2024-31835");
  script_xref(name:"URL", value:"https://github.com/paragbagul111/CVE-2024-33209?tab=readme-ov-file#cve-2024-33209");
  script_xref(name:"URL", value:"https://github.com/paragbagul111/CVE-2024-33210");

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

if (version_is_less_equal(version: version, test_version: "1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
