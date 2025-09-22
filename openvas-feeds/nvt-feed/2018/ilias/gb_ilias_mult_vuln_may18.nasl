# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112288");
  script_version("2023-11-15T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-11-15 05:05:25 +0000 (Wed, 15 Nov 2023)");
  script_tag(name:"creation_date", value:"2018-05-18 09:30:08 +0200 (Fri, 18 May 2018)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-15 19:39:00 +0000 (Fri, 15 Jun 2018)");

  script_cve_id("CVE-2018-11117", "CVE-2018-11118", "CVE-2018-11119", "CVE-2018-11120");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 5.1.27, 5.2.16, 5.3.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_http_detect.nasl");
  script_mandatory_keys("ilias/detected");

  script_tag(name:"summary", value:"ILIAS eLearning is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-11117: Services/Feeds/classes/class.ilExternalFeedItem.php in ILIAS has XSS via a link
  attribute.

  - CVE-2018-11118: The RSS subsystem in ILIAS has XSS via a URI to
  Services/Feeds/classes/class.ilExternalFeedItem.php.

  - CVE-2018-11119: ILIAS redirects a logged-in user to a third-party site via the return_to_url
  parameter.

  - CVE-2018-11120: Services/COPage/classes/class.ilPCSourceCode.php in ILIAS has XSS.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ILIAS version 5.1.x prior to 5.1.26, 5.2.x prior to 5.2.15 and
  5.3.x prior to 5.3.4");

  script_tag(name:"solution", value:"Update to version 5.1.27, 5.2.16, 5.3.5 or later.");

  script_xref(name:"URL", value:"https://www.ilias.de/docu/goto.php?target=st_229");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:ilias:ilias";

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "5.1.0", test_version2: "5.1.26")) {
  vuln = TRUE;
  fix = "5.1.27";
} else if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.15")) {
  vuln = TRUE;
  fix = "5.2.16";
} else if (version_in_range(version: version, test_version: "5.3.0", test_version2: "5.3.4")) {
  vuln = TRUE;
  fix = "5.3.5";
}

if (vuln) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
