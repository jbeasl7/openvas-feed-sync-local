# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:archiva";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808280");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-08-02 19:48:44 +0530 (Tue, 02 Aug 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-16 18:29:00 +0000 (Tue, 16 Apr 2019)");

  script_cve_id("CVE-2016-4469", "CVE-2016-5005");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Archiva < 2.2.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_archiva_http_detect.nasl");
  script_mandatory_keys("apache/archiva/detected");

  script_tag(name:"summary", value:"Apache Archiva is prone to cross-site request forgery (CSRF) and
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An insufficient validation of user supplied input via HTTP POST parameter
  'connector.sourceRepoId' to 'admin/addProxyConnector_commit.action'.

  - The application lacks a Cross-Site Request Forgery protection to certain HTTP POST-based
  functions");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to perform
  sensitive administrative actions and to inject arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Apache Archiva version 1.3.9 and prior.");

  script_tag(name:"solution", value:"Update to version 2.2.1 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137870");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91707");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91703");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137869");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/538877/100/0/threaded");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
