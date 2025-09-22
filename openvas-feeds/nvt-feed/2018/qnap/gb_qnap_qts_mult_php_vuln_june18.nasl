# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:qts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813519");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2018-06-11 17:13:13 +0530 (Mon, 11 Jun 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:58:00 +0000 (Wed, 20 Jul 2022)");

  script_cve_id("CVE-2016-1283", "CVE-2017-16642", "CVE-2018-5711", "CVE-2018-5712");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple PHP Vulnerabilities (NAS-201805-10)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The pcre_compile2 function in pcre_compile.c in PCRE 8.38 mishandles the
    multiple patterns with named subgroups.

  - An error in the date extension's 'timelib_meridian' handling of 'front of'
    and 'back of' directives.

  - An input validation error on the PHAR 404 error page via the URI of a request
    for a .phar file.

  - An integer signedness error in gd_gif_in.c in the GD Graphics Library
    (aka libgd).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to access
  sensitive information on the NAS, launch denial-of-service (DoS), or Cross-Site-Scripting (XSS)
  attacks.");

  script_tag(name:"affected", value:"QNAP QTS versions 4.3.3 through 4.3.3 build 20180126 and
  4.3.4 through 4.3.4 build 20180215.");

  script_tag(name:"solution", value:"Update to version 4.3.3 build 20180402, 4.3.4 build 20180315 or
  later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en-us/security-advisory/nas-201805-10");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version_is_less(version: version, test_version: "4.3.3")) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20180402");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "4.3.3") &&
   (!build || version_is_less(version: build, test_version: "20180402"))) {
  report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20180402");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^4\.3\.4") {
   if (!build || version_is_less(version: build, test_version: "20180315")) {
    report = report_fixed_ver(installed_version: version, installed_build: build, fixed_version: "4.3.4", fixed_build: "20180315");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
