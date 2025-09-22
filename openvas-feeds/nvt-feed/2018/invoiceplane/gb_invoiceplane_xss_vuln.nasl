# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:invoiceplane:invoiceplane";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140858");
  script_version("2025-04-07T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-04-07 05:39:52 +0000 (Mon, 07 Apr 2025)");
  script_tag(name:"creation_date", value:"2018-03-06 10:57:13 +0700 (Tue, 06 Mar 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-26 13:23:00 +0000 (Fri, 26 Apr 2019)");

  script_cve_id("CVE-2017-18217");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("InvoicePlane < 1.5.5 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_invoiceplane_http_detect.nasl");
  script_mandatory_keys("invoiceplane/detected");

  script_tag(name:"summary", value:"The Email address and Web address parameters are vulnerable to
  cross-site scripting, related to application/modules/clients/views/view.php,
  application/modules/invoices/views/view.php and application/modules/quotes/views/view.php.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"InvoicePlane prior to version 1.5.5.");

  script_tag(name:"solution", value:"Update to version 1.5.5 or later.");

  script_xref(name:"URL", value:"https://github.com/InvoicePlane/InvoicePlane/pull/542");
  script_xref(name:"URL", value:"https://github.com/InvoicePlane/InvoicePlane/pull/551");
  script_xref(name:"URL", value:"http://blog.isecurion.com/2018/04/23/invoice-plane-v1-5-cross-site-scripting-vulnerability/");

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

if (version_is_less(version: version, test_version: "1.5.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
