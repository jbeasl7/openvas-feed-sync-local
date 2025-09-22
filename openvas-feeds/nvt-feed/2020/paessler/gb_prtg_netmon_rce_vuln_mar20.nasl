# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:paessler:prtg_network_monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143666");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-04-01 04:51:21 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-25 16:15:00 +0000 (Thu, 25 Jun 2020)");

  script_cve_id("CVE-2020-10374");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PRTG Network Monitor < 20.1.57.1745 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_prtg_network_monitor_detect.nasl");
  script_mandatory_keys("prtg_network_monitor/installed");

  script_tag(name:"summary", value:"PRTG Network Monitor is prone to an unauthenticated remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"With a carefully crafted POST request, a possible attacker can perform an RCE
  by executing a UNC path on the PRTG core server system with the security context of the PRTG core server service,
  without the need of an authenticated session.

  By utilizing the what parameter of the screenshot function that is used in the Contact Support form in PRTG, for
  example, an attacker is able to inject a crafted, URI-compatible UNC path that is executed as part of the caller
  chain down to the Chromium engine to create the screenshot.");

  script_tag(name:"affected", value:"PRTG Network Monitor versions 19.2.50 through 20.1.56.");

  script_tag(name:"solution", value:"Update to version 20.1.57.1745 or later.");

  script_xref(name:"URL", value:"https://www.paessler.com/prtg/history/stable#20.1.57.1745");
  script_xref(name:"URL", value:"https://kb.paessler.com/en/topic/87668-how-can-i-mitigate-cve-2020-10374-until-i-can-update");

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

if (version_is_greater_equal(version: version, test_version: "19.2.50") &&
    version_is_less(version: version, test_version: "20.1.57.1745")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.1.57.1745", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
