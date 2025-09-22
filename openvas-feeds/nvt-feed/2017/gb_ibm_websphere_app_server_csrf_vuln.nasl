# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811019");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-05-05 11:13:19 +0530 (Fri, 05 May 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)");

  script_cve_id("CVE-2017-1194");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server CSRF Vulnerability (swg22001226)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere_or_liberty/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a cross-site
  request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the application fails to properly validate
  HTTP requests.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow a remote
  attacker to perform certain unauthorized actions and gain access to the affected application.
  Other attacks are also possible.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server versions 9.0.0.0 through
  9.0.0.3, 8.5.0.0 through 8.5.5.11, 8.0.0.0 through 8.0.0.13, 7.0.0.0 through 7.0.0.43 amd
  WebSphere Application Server Liberty prior to 17.0.0.2.");

  script_tag(name:"solution", value:"Update to version 9.0.0.4, 8.5.5.12, 8.0.0.14, 7.0.0.45 or
  later (WebSphere Application Server) or version 17.0.0.2 or later (WebSphere Liberty).");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22001226");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98142");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (get_kb_item("ibm/websphere/liberty/detected")) {
  if (version_is_less(version: version, test_version: "17.0.0.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "17.0.0.2");
     security_message(port: 0, data: report);
     exit(0);
  }
} else {
  if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.45")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.45");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.0.14")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.14");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.5.12")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.5.5.12");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.0.0.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.0.0.4");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
