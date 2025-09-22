# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:navis:webaccess";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106195");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-08-23 08:07:26 +0700 (Tue, 23 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-22 17:02:00 +0000 (Mon, 22 Aug 2016)");

  script_cve_id("CVE-2016-5817");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Navis WebAccess SQL Injection Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_navis_webaccess_detect.nasl");
  script_mandatory_keys("navis_webaccess/installed");

  script_tag(name:"summary", value:"Navis WebAccess is prone to an SQL injection vulnerability.");

  script_tag(name:"insight", value:"The WebAccess application does not properly sanitize input that
may allow a remote attacker to read, modify, and affect availability of data in the SQL database.");

  script_tag(name:"impact", value:"Successful exploitation of the vulnerability may allow a remote
attacker to compromise the confidentiality, integrity, and availability of the SQL database.");

  script_tag(name:"affected", value:"Navis WebAccess, all versions released prior to August 10, 2016");

  script_tag(name:"solution", value:"Install the patch provided by the vendor.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-231-01");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40216/");

  script_tag(name:"vuldetect", value:"Tries to cause an SQL error and checks the response.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/express/showNotice.do?report_type=1&GKEY=2'";

if (http_vuln_check(port: port, url: url, pattern: "ORA-00933: SQL command not properly ended")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
