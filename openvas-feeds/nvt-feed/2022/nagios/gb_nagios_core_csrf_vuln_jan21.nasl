# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126251");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"creation_date", value:"2022-12-13 07:00:06 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-02 21:15:00 +0000 (Tue, 02 Mar 2021)");

  script_cve_id("CVE-2020-35269");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Vulnerability depends on external configuration

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Nagios Core CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nagios_http_detect.nasl");
  script_mandatory_keys("nagios/detected");

  script_tag(name:"summary", value:"Nagios Core is prone to a cross-site request forgery
  (CSRF) vulnerability, if the Apache Webserver configuration has not been changed to
  include SSL protection.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cross-Site Request Forgery (CSRF) in many functions, like adding
  or deleting for hosts or servers.");

  script_tag(name:"affected", value:"Al versions of Nagios Core.");

  script_tag(name:"solution", value:"To mitigate the issue the vendor suggests to change the apache
  configuration on the server to include SSL protection for both /nagios and /nagios/cgi-bin.");

  script_xref(name:"URL", value:"https://github.com/NagiosEnterprises/nagioscore/issues/809#issuecomment-760331317");

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

report = report_fixed_ver(installed_version: version, fixed_version: "See solution", install_path: location);
security_message(port: port, data: report);

exit(0);
