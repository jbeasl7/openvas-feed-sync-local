# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cs-cart:cs-cart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106398");
  script_version("2025-05-29T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"creation_date", value:"2016-11-18 10:07:02 +0700 (Fri, 18 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CS-Cart < 4.4.2 XXE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cscart_detect.nasl");
  script_mandatory_keys("cs_cart/installed");

  script_tag(name:"summary", value:"CS-Cart is prone to an XML external entity (XXE) injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a XML External Entity injection (XXE) vulnerability in
  the Twigmo Addon and in the Amazon Payment Addon.");

  script_tag(name:"impact", value:"An unauthenticated attacker may read arbitrary files or conduct a
  denial of service attack.");

  script_tag(name:"solution", value:"Update to CS-Cart version 4.4.2 or later which:

  - removes the vulnerable Twigmo Addon (deprecated)

  - fixes the XXE vulnerability in the Amazon Payment Addon");

  script_xref(name:"URL", value:"http://docs.cs-cart.com/4.5.x/history/442.html#cs-cart-4-4-2-changelog");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40770/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_less(version:vers, test_version:"4.4.2")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "4.4.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
