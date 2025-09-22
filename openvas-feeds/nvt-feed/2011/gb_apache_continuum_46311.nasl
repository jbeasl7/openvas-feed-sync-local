# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:continuum";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103074");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-02-11 13:54:50 +0100 (Fri, 11 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-0533");

  script_name("Apache Continuum Cross Site Scripting Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_apache_continuum_detect.nasl");
  script_mandatory_keys("apache_continuum/installed");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
details.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Apache Continuum is prone to a cross-site scripting vulnerability
because it fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks.

Apache Continuum 1.3.6 and 1.4.0 (Beta) are vulnerable. Other versions
may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46311");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1066056");
  script_xref(name:"URL", value:"http://continuum.apache.org/security.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_equal(version: version, test_version: "1.3.6")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"Equal to 1.3.6");
  security_message(port: port, data: report);
  exit(0);
}
else if(version_is_equal(version: version, test_version: "1.4.0")) {
  if (!build = get_kb_item("apache_continuum/build"))
    exit(0);
  if(version_is_less_equal(version:build, test_version: "939198")) {
    report = report_fixed_ver(installed_version:build, vulnerable_range:"Less than or equal to 939198");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
