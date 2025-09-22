# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140387");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-09-21 16:15:51 +0700 (Thu, 21 Sep 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-25 08:24:00 +0000 (Wed, 25 Oct 2017)");

  script_cve_id("CVE-2017-14618", "CVE-2017-14619", "CVE-2017-15727", "CVE-2017-15728",
                "CVE-2017-15729", "CVE-2017-15730", "CVE-2017-15731", "CVE-2017-15732",
                "CVE-2017-15733", "CVE-2017-15734", "CVE-2017-15735", "CVE-2017-15808",
                "CVE-2017-15809");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ < 2.9.9 Multiple XSS And CSRF Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyfaq_http_detect.nasl");
  script_mandatory_keys("phpmyfaq/detected");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple cross-site scripting (XSS) and
  cross-site request forgery (CSRF) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-14618: Cross-site scripting (XSS) vulnerability in inc/PMF/Faq.php in phpMyFAQ allows
  remote attackers to inject arbitrary web script or HTML via the Questions field in an 'Add New
  FAQ' action script or HTML via the 'Title of your FAQ' field in the Configuration Module.

  - CVE-2017-14619: Cross-site scripting (XSS) vulnerability in phpMyFAQ allows remote attackers to
  inject arbitrary web script or HTML via the 'Title of your FAQ' field in the Configuration Module

  - CVE-2017-15727: Stored Cross-site Scripting (XSS) via an HTML attachment

  - CVE-2017-15728: Stored Cross-site Scripting (XSS) via metaDescription or metaKeywords.

  - CVE-2017-15729: Cross-Site Request Forgery (CSRF) for adding a glossary

  - CVE-2017-15730: Cross-Site Request Forgery (CSRF) in admin/stat.ratings.php

  - CVE-2017-15731: Cross-Site Request Forgery (CSRF) in admin/stat.adminlog.php

  - CVE-2017-15732: Cross-Site Request Forgery (CSRF) in admin/news.php

  - CVE-2017-15733: Cross-Site Request Forgery (CSRF) in admin/ajax.attachment.php and
  admin/att.main.php

  - CVE-2017-15734: Cross-Site Request Forgery (CSRF) in admin/stat.main.php

  - CVE-2017-15735: Cross-Site Request Forgery (CSRF) for modifying a glossary

  - CVE-2017-15808: CSRF in admin/ajax.config.php

  - CVE-2017-15809: XSS in admin/tags.main.php via a crafted tag");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct XSS and
  CSRF attacks.");

  script_tag(name:"affected", value:"phpMyFAQ version 2.9.8 and prior.");

  script_tag(name:"solution", value:"Update to version 2.9.9 or later.");

  script_xref(name:"URL", value:"https://www.phpmyfaq.de/security/advisory-2017-10-19");
  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/commit/30b0025e19bd95ba28f4eff4d259671e7bb6bb86");
  script_xref(name:"URL", value:"https://github.com/thorsten/phpMyFAQ/commit/cb648f0d5690b81647dd5c9efe942ebf6cce7da9");

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

if (version_is_less_equal(version: version, test_version: "2.9.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
