# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only.

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902610");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-3271");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server < 7.0.0.14 Multiple CSRF Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to cross-site request
  forgery (CSRF) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to by improper validation of user-supplied
  input in the Global Security panel and master configuration save functionality which allows
  attacker to force a logged-in administrator to perform unwanted actions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote users to gain
  sensitive information or conduct other malicious activities.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 7.0.0.13 and
  prior.");

  script_tag(name:"solution", value:"Update to version 7.0.0.14 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44909");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48305");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68069");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/IBM-WebSphere-CSRF");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "7.0.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.14");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
