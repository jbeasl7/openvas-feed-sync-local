# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:solarwinds:orion_network_performance_monitor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105966");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-03-06 12:47:16 +0700 (Fri, 06 Mar 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-9566");

  script_name("SolarWinds Network Performance Monitor Multiple SQLi Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_solarwinds_orion_npm_consolidation.nasl");
  script_mandatory_keys("solarwinds/orion/npm/detected");

  script_tag(name:"summary", value:"SolarWinds Network Performance Monitor is prone to multiple SQL
  injection (SQLi) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"On both the GetAccounts and GetAccountGroups endpoints, the
  'sort' and 'dir' parameters are susceptible to boolean-/time-based, and stacked injections. The attacker
  has to be authenticated but it can be even exploited under a guest account.");

  script_tag(name:"impact", value:"An authenticated attacker might execute arbitrary SQL commands
  to compromise the application, access or modify data, or exploit latent vulnerabilities in the
  underlying database.");

  script_tag(name:"affected", value:"SolarWinds NPM 11.4 and previous.");

  script_tag(name:"solution", value:"Upgrade to SolarWinds NPM 11.5 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Mar/18");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "11.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
