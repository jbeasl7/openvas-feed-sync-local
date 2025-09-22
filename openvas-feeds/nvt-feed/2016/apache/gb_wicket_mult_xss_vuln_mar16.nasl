# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:wicket";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807585");
  script_version("2025-04-01T05:39:41+0000");
  script_tag(name:"last_modification", value:"2025-04-01 05:39:41 +0000 (Tue, 01 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-05-16 10:44:34 +0530 (Mon, 16 May 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-12 18:23:00 +0000 (Tue, 12 Feb 2019)");

  script_cve_id("CVE-2015-5347", "CVE-2015-7520");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Wicket Multiple XSS Vulnerabilities (Mar 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_wicket_consolidation.nasl");
  script_mandatory_keys("apache/wicket/detected");

  script_tag(name:"summary", value:"Apache Wicket is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2015-7520: Insufficient validation of user supplied input via 'value' attribute in
  RadioGroup and CheckBoxMultipleChoice classes.

  - CVE-2015-5347: Insufficient validation of user supplied input via 'ModalWindow title' in
  getWindowOpenJavaScript function in
  org.apache.wicket.extensions.ajax.markup.html.modal.ModalWindow class.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Apache Wicket versions 1.5.x prior to 1.5.15, 6.x prior to
  6.22.0 and 7.x prior to 7.2.0.");

  script_tag(name:"solution", value:"Update to version 1.5.15, 6.22.0, 7.2.0 or later.");

  script_xref(name:"URL", value:"https://wicket.apache.org/news/2016/03/02/cve-2015-7520.html");
  script_xref(name:"URL", value:"https://wicket.apache.org/news/2016/03/01/cve-2015-5347.html");

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

if (version_is_less(version: version, test_version: "1.5.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.21.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.22.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
