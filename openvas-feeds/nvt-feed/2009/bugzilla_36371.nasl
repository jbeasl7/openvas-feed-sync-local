# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:bugzilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100286");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-02 19:48:14 +0200 (Fri, 02 Oct 2009)");
  script_cve_id("CVE-2009-3125");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Bugzilla 'Bug.search()' WebService Function SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36371");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=515191");
  script_xref(name:"URL", value:"http://www.bugzilla.org/security/3.0.8/");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Bugzilla is prone to an SQL-injection vulnerability because it fails to
  sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Bugzilla 3.3.2 through 3.4.1 Bugzilla 3.5");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version:version, test_version:"3.4", test_version2:"3.4.1") ||
    version_in_range(version:version, test_version:"3.3", test_version2:"3.3.4") ||
    version_is_equal(version:version, test_version:"3.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See references");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);