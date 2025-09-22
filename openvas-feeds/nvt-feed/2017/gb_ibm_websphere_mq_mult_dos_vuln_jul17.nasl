# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_mq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140259");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-08-01 09:50:24 +0700 (Tue, 01 Aug 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-17 18:34:00 +0000 (Mon, 17 Jul 2017)");

  script_cve_id("CVE-2017-1236", "CVE-2017-1285");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere MQ Multiple Denial of Service Vulnerabilities (Jul 2017)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ibm_websphere_mq_consolidation.nasl");
  script_mandatory_keys("ibm_websphere_mq/detected");

  script_tag(name:"summary", value:"IBM WebSphere MQ is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"IBM WebSphere MQ is prone to multiple vulnerabilities:

  - IBM WebSphere MQ could allow an authenticated user to potentially cause a denial of service by saving an
incorrect channel status inquiry. (CVE-2017-1236)

  - IBM WebSphere MQ could allow an authenticated user with authority to send a specially crafted message that
would cause a channel to remain in a running state but not process messages. (CVE-2017-1285)");

  script_tag(name:"affected", value:"IBM WebSphere MQ versions 9.0.1 and 9.0.2");

  script_tag(name:"solution", value:"Update to version 9.0.3 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22003510");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99505");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99538");
  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22003856");

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

if (version_in_range(version: version, test_version: "9.0.1", test_version2: "9.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
