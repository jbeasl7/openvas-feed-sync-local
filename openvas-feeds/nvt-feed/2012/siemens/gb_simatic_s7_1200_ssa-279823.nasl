# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:siemens:simatic_s7_1200";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103584");
  script_version("2025-04-22T10:32:18+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2012-3040");

  script_name("Siemens SIMATIC S7-1200 PLC 'web server' Component XSS Vulnerability (SSA-279823)");

  script_xref(name:"URL", value:"https://cert-portal.siemens.com/productcert/html/ssa-279823.html");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-12-283-01");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55841");

  script_tag(name:"last_modification", value:"2025-04-22 10:32:18 +0000 (Tue, 22 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-10-10 12:27:02 +0200 (Wed, 10 Oct 2012)");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_siemens_simatic_s7_consolidation.nasl");
  script_mandatory_keys("siemens/simatic_s7/detected");

  script_tag(name:"summary", value:"Siemens SIMATIC S7-1200 Programmable Logic Controller (PLC) is
  prone to a cross-site scripting (XSS) vulnerability because it fails to properly sanitize
  user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This can allow
  the attacker to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if(version_is_less_equal(version: version, test_version: "3.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
