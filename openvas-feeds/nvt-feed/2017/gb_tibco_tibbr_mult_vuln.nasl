# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tibco:tibbr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140605");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-14 14:49:06 +0700 (Thu, 14 Dec 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:28:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-5530", "CVE-2017-5534");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TIBCO tibbr Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tibco_tibbr_detect.nasl");
  script_mandatory_keys("tibbr/installed");

  script_tag(name:"summary", value:"TIBCO tibbr is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"TIBCO tibbr is prone to multiple vulnerabilities:

  - SAML protocol handling errors (CVE-2017-5530)

  - Improper sandboxing of a third-party component (CVE-2017-5534)");

  script_tag(name:"affected", value:"tibbr version 5.2.1 and prior, 6.0.x and 7.0.0");

  script_tag(name:"solution", value:"Update to 5.2.2, 6.0.2, 7.0.1 or later.");

  script_xref(name:"URL", value:"https://www.tibco.com/support/advisories/2017/12/tibco-security-advisory-december-12-2017-tibbr-2017-5530");
  script_xref(name:"URL", value:"https://www.tibco.com/support/advisories/2017/12/tibco-security-advisory-december-12-2017-tibbr-2017-5534");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.2");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.2");
  security_message(port: port, data: report);
  exit(0);
}

if (version == "7.0.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
