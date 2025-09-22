# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_mq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106909");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-06-27 12:09:42 +0700 (Tue, 27 Jun 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-1117");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere MQ Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ibm_websphere_mq_detect.nasl");
  script_mandatory_keys("ibm_websphere_mq/detected");

  script_tag(name:"summary", value:"IBM WebSphere MQ could allow an authenticated user to cause a denial of
  service to the MQXR channel when trace is enabled.");

  script_tag(name:"affected", value:"IBM WebSphere MQ versions 8.0.0.0 - 8.0.0.5, 9.0.1 and 9.0.0.0.");

  script_tag(name:"solution", value:"Update to version 8.0.0.6, 9.0.0.1, 9.0.2 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22001468");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_in_range(version: version, test_version: "8.0.0.0", test_version2: "8.0.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.6", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "9.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.2", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "9.0.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.0.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
