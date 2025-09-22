# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147750");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2022-03-04 02:58:06 +0000 (Fri, 04 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-16 15:26:00 +0000 (Wed, 16 Mar 2022)");

  script_cve_id("CVE-2022-23709");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana Authorization Vulnerability (ESA-2022-03)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_http_detect.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Elastic Kibana is prone to an authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in Kibana in which users with Read access
  to the Uptime feature could modify alerting rules. A user with this privilege would be able to
  create new alerting rules or overwrite existing ones. However, any new or modified rules would
  not be enabled, and a user with this privilege could not modify alerting connectors. This
  effectively means that Read users could disable existing alerting rules.");

  script_tag(name:"affected", value:"Elastic Kibana version 7.7.0 through 7.17.0 and version
  8.0.0.");

  script_tag(name:"solution", value:"Update to version 7.17.1, 8.0.1 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-17-1-security-update/298447");

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

if (version_in_range(version: version, test_version: "7.7.0", test_version2: "7.17.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.17.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "8.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
