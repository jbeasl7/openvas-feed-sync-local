# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sensiolabs:symfony";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.144528");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-09-07 05:17:20 +0000 (Mon, 07 Sep 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-25 19:15:00 +0000 (Fri, 25 Sep 2020)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Patches are available

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-15094");

  script_name("Symfony 4.3.0 - 4.4.12, 5.0.0 - 5.1.4 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symfony_consolidation.nasl");
  script_mandatory_keys("symfony/detected");

  script_tag(name:"summary", value:"Symfony is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The CachingHttpClient class from the HttpClient Symfony component relies on
  the HttpCache class to handle requests. HttpCache uses internal headers like X-Body-Eval and X-Body-File to
  control the restoration of cached responses. The class was initially written with surrogate caching and ESI
  support in mind (all HTTP calls come from a trusted backend in that scenario). But when used by CachingHttpClient
  and if an attacker can control the response for a request being made by the CachingHttpClient, remote code
  execution is possible.");

  script_tag(name:"affected", value:"Symfony versions 4.3.0 to 4.4.12 and 5.0.0 to 5.1.4.");

  script_tag(name:"solution", value:"Update to version 4.4.13, 5.1.5 or later.");

  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2020-15094-prevent-rce-when-calling-untrusted-remote-with-cachinghttpclient");
  script_xref(name:"URL", value:"https://github.com/symfony/symfony/security/advisories/GHSA-754h-5r27-7x3r");

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

if (version_in_range(version: version, test_version: "4.3.0", test_version2: "4.4.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
