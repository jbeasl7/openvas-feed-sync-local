# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:identity_services_engine";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140273");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-08-03 10:23:50 +0700 (Thu, 03 Aug 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-6747");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Identity Services Engine Authentication Bypass Vulnerability (cisco-sa-20170802-ise)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ise_consolidation.nasl");
  script_mandatory_keys("cisco/ise/detected");

  script_tag(name:"summary", value:"A vulnerability in the authentication module of Cisco Identity
  Services Engine (ISE) could allow an unauthenticated, remote attacker to bypass local
  authentication.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling of authentication
  requests and policy assignment for externally authenticated users. An attacker could exploit this
  vulnerability by authenticating with a valid external user account that matches an internal
  username and incorrectly receiving the authorization policy of the internal account.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to have Super Admin
  privileges for the ISE Admin portal.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170802-ise");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

patch = get_kb_item("cisco/ise/patch");

if (version =~ "1\.3\.0") {
  report = report_fixed_ver(installed_version: version, installed_patch: patch,
                            fixed_version: "1.4.0", fixed_patch: "11");
  security_message(port: 0, data: report);
}

if (version =~ "1\.4\.0") {
  if (!patch || version_is_less(version: patch, test_version: "11")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "1.4.0", fixed_patch: "11");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "2\.0\.0") {
  if (!patch || version_is_less(version: patch, test_version: "5")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "2.0.0", fixed_patch: "5");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "2\.0\.1") {
  if (!patch || version_is_less(version: patch, test_version: "5")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "2.0.1", fixed_patch: "5");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "2\.1\.0") {
  if (!patch || version_is_less(version: patch, test_version: "2")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "2.1.0", fixed_patch: "2");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
