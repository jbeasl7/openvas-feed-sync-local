# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:archiva";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106825");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-05-23 14:41:11 +0700 (Tue, 23 May 2017)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-16 18:29:00 +0000 (Tue, 16 Apr 2019)");

  script_cve_id("CVE-2017-5657");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Archiva < 2.2.3 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_archiva_http_detect.nasl");
  script_mandatory_keys("apache/archiva/detected");

  script_tag(name:"summary", value:"Apache Archiva is prone to a cross-site request forgery (CSRF)
  vulnerability in various REST endpoints.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Several REST service endpoints of Apache Archiva are not
  protected against CSRF attacks.");

  script_tag(name:"impact", value:"A malicious site opened in the same browser as the archiva site,
  may send HTML response that performs arbitrary actions on archiva services, with the same rights
  as the active archiva session (e.g. administrator rights).");

  script_tag(name:"affected", value:"Apache Archiva prior to version 2.2.3.");

  script_tag(name:"solution", value:"Update to version 2.2.3 or later.");

  script_xref(name:"URL", value:"https://archiva.apache.org/security.html#CVE-2017-5657");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
