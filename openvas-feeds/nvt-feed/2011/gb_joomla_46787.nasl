# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103114");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-03-09 13:38:24 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Joomla! < 1.6.1 Multiple Security Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46787");
  script_xref(name:"URL", value:"http://www.joomla.org/announcements/release-news/5350-joomla-161-released.html");

  script_tag(name:"summary", value:"Joomla! is prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - An SQL-injection issue

  - A path-disclosure vulnerability

  - Multiple cross-site scripting issues

  - Multiple information disclosure vulnerabilities

  - A URI-redirection vulnerability

  - A security bypass vulnerability

  - A cross-site request-forgery vulnerability

  - A denial-of-service vulnerability");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site,
  steal cookie-based authentication credentials, disclose or modify sensitive information, exploit
  latent vulnerabilities in the underlying database, deny service to legitimate users, redirect a
  victim to a potentially malicious site, or perform unauthorized actions. Other attacks are also
  possible.");

  script_tag(name:"affected", value:"Joomla! versions prior to 1.6.1.");

  script_tag(name:"solution", value:"The vendor released a patch. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.6.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
