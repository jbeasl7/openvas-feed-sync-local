# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141795");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-12-18 10:01:00 +0700 (Tue, 18 Dec 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-11 18:15:00 +0000 (Sat, 11 Apr 2020)");

  script_cve_id("CVE-2018-18245");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nagios Core <= 4.4.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_http_detect.nasl");
  script_mandatory_keys("nagios/detected");

  script_tag(name:"summary", value:"Nagios Core 4.4.2 has XSS via the alert summary reports of plugin results, as
  demonstrated by a SCRIPT element delivered by a modified check_load plugin to NRPE.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Nagios Core version 4.4.2 and probably prior.");

  script_tag(name:"solution", value:"Update to version 4.4.3 or later.");

  script_xref(name:"URL", value:"https://herolab.usd.de/wp-content/uploads/sites/4/2018/12/usd20180026.txt");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/NagiosEnterprises/nagioscore/master/Changelog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
