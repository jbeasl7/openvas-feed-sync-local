# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:imagely:nextgen_gallery";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145366");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2021-02-11 09:12:39 +0000 (Thu, 11 Feb 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-12 15:24:00 +0000 (Fri, 12 Feb 2021)");

  script_cve_id("CVE-2020-35942", "CVE-2020-35943");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress NextGEN Gallery Plugin < 3.5.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/nextgen-gallery/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Imagely NextGen Gallery' is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Cross-Site Request Forgery (CSRF) leading to XSS and RCE via file upload and LFI (CVE-2020-35942)

  - Cross-Site Request Forgery (CSRF) leading to file upload (CVE-2020-35943)");

  script_tag(name:"impact", value:"Exploitation of these vulnerabilities could lead to a site
  takeover, malicious redirects, spam injection, phishing, and other attacks.");

  script_tag(name:"affected", value:"WordPress NextGEN Gallery plugin prior to version 3.5.0.");

  script_tag(name:"solution", value:"Update to version 3.5.0 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/02/severe-vulnerabilities-patched-in-nextgen-gallery-affect-over-800000-wordpress-sites/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
