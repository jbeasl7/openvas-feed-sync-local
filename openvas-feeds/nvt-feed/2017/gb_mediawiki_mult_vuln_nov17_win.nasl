# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112125");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-11-16 11:28:15 +0100 (Thu, 16 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-28 16:56:00 +0000 (Tue, 28 Nov 2017)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_cve_id("CVE-2017-8808", "CVE-2017-8809", "CVE-2017-8810", "CVE-2017-8811",
                "CVE-2017-8812", "CVE-2017-8814", "CVE-2017-8815");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki Multiple Vulnerabilities (Nov 2017) - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - XSS when the $wgShowExceptionDetails setting is false and the browser sends non-standard URL escaping. (CVE-2017-8808)

  - A Reflected File Download vulnerability in api.php. (CVE-2017-8809)

  - When a private wiki is configured, it provides different error messages for failed login attempts - depending on whether the username exists -
which allows remote attackers to enumerate account names and conduct brute-force attacks via a series of requests. (CVE-2017-8810)

  - The implementation of raw message parameter expansion allows HTML mangling attacks. (CVE-2017-8811)

  - Allowing remote attackers to inject > (greater than) characters via the id attribute of a headline. (CVE-2017-8812)

  - The language converter allows attackers to replace text inside tags via a rule definition followed by 'a lot of junk'. (CVE-2017-8814)

  - The language converter allows attribute injection attacks via glossary rules. (CVE-2017-8815)");

  script_tag(name:"solution", value:"Update to version 1.27.4, 1.28.3, 1.29.2 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2017-November/000216.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.27.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.27.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.28.0", test_version2: "1.28.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.28.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.29.0", test_version2: "1.29.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.29.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
