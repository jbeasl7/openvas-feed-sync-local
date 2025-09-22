# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:piwigo:piwigo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140626");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-12-22 15:02:56 +0700 (Fri, 22 Dec 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-04 20:50:00 +0000 (Thu, 04 Jan 2018)");

  script_cve_id("CVE-2017-17774", "CVE-2017-17775", "CVE-2017-17826", "CVE-2017-17827", "CVE-2017-17822",
                "CVE-2017-17823", "CVE-2017-17824", "CVE-2017-17825");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Piwigo Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Piwigo is prone to multiple vulnerabilities:

  - admin/configuration.php has a CSRF. (CVE-2017-17774)

  - XSS via the name parameter in an admin.php?page=album-3-properties request. (CVE-2017-17775)

  - Persistent XSS via the gallery_title parameter in an admin.php?page=configuration&section=main request. An
attacker can exploit this to hijack a client's browser along with the data stored in it. (CVE-2017-17826)

  - Cross-Site Request Forgery via /admin.php?page=configuration&section=main or
/admin.php?page=batch_manager&mode=unit. An attacker can exploit this to coerce an admin user into performing
unintended actions. (CVE-2017-17827)

  - SQL Injection via the /admin/user_list_backend.php sSortDir_0 parameter. An attacker can exploit this to gain
access to the data in a connected MySQL database. (CVE-2017-17822)

  - SQL Injection via the admin/configuration.php order_by array parameter. An attacker can exploit this to gain
access to the data in a connected MySQL database. (CVE-2017-17823)

  - SQL Injection via the admin/batch_manager_unit.php element_ids parameter in unit mode. An attacker can exploit
this to gain access to the data in a connected MySQL database. (CVE-2017-17824)

  - Persistent Cross Site Scripting via tags-* array parameters in an admin.php?page=batch_manager&mode=unit
request. An attacker can exploit this to hijack a client's browser along with the data stored in it.
(CVE-2017-17825)");

  script_tag(name:"affected", value:"Piwigo version 2.9.2 and probably prior.");

  script_tag(name:"solution", value:"Update to version 2.9.3 or later.");

  script_xref(name:"URL", value:"https://github.com/d4wner/Vulnerabilities-Report/blob/master/piwigo.md");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/822");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/823");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/825");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/826");
  script_xref(name:"URL", value:"https://github.com/sahildhar/sahildhar.github.io/blob/master/research/reports/Piwigo_2.9.2/Stored%20XSS%20Vulnerabilities%20in%20Piwigo%202.9.2.md");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
