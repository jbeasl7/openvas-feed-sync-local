# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145941");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-05-14 04:51:46 +0000 (Fri, 14 May 2021)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-21 16:40:00 +0000 (Fri, 21 May 2021)");

  script_cve_id("CVE-2021-22136");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana Timeout Bypass Vulnerability (ESA-2021-07)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_http_detect.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  script_tag(name:"summary", value:"Kibana is prone to a timeout bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw in Kibana's session timeout was discovered where the
  xpack.security.session.idleTimeout setting is not being respected. This was caused by background
  polling activities unintentionally extending authenticated users sessions, preventing a user
  session from timing out.");

  script_tag(name:"affected", value:"Kibana versions prior to 6.8.15 and 7.12.0.");

  script_tag(name:"solution", value:"Update to version 6.8.15, 7.12.0 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/elastic-stack-7-12-0-and-6-8-15-security-update/268125");

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

if (version_is_less(version: version, test_version: "6.8.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.8.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^7\." && version_is_less(version: version, test_version: "7.12.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.12.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
