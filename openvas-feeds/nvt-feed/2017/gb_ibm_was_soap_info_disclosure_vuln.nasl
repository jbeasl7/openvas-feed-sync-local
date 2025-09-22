# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811129");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-06-21 16:24:33 +0530 (Wed, 21 Jun 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-13 16:53:00 +0000 (Tue, 13 Jun 2017)");

  script_cve_id("CVE-2016-9736");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server Information Disclosure Vulnerability (swg21991469)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to information
  discloure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to usage of malformed SOAP requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to obtain
  sensitive information that may lead to further attacks.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 9.0.0.0 through
  9.0.0.1, 8.5.0.0 through 8.5.5.10 and 8.0.0.0 through 8.0.0.12.");

  script_tag(name:"solution", value:"Update to version 9.0.0.2, 8.5.5.11, 8.0.0.13 or later.");

  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21991469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96076");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.13");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.5.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.5.11");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.0.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.0.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
