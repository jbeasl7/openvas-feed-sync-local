# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147170");
  script_version("2025-09-03T14:11:39+0000");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2021-11-17 03:26:49 +0000 (Wed, 17 Nov 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-23 18:20:00 +0000 (Tue, 23 Nov 2021)");

  script_cve_id("CVE-2021-37938");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Elastic Kibana Directory Traversal Vulnerability (ESA-2021-26)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("elastic/kibana/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Kibana is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that on Windows operating systems
  specifically, Kibana was not validating a user supplied path, which would load .pbf files.
  Because of this, a malicious user could arbitrarily traverse the Kibana host to load internal
  files ending in the .pbf extension.");

  script_tag(name:"affected", value:"Kibana version 7.9.0 through 7.15.1 on Windows.");

  script_tag(name:"solution", value:"Update to version 7.15.2 or later.");

  script_xref(name:"URL", value:"https://discuss.elastic.co/t/kibana-7-15-2-security-update/288923");

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

if (version_in_range(version: version, test_version: "7.9.0", test_version2: "7.15.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.15.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
