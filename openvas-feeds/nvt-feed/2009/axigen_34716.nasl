# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:axigen:axigen_mail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100177");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_cve_id("CVE-2009-1484");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Axigen Mail Server HTML Injection Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_axigen_webmail_http_detect.nasl");
  script_mandatory_keys("axigen/detected");

  script_tag(name:"solution", value:"Reports indicate that fixes are available. Please contact the vendor for
  more information.");

  script_tag(name:"summary", value:"Axigen Mail Server is prone to an HTML-injection vulnerability because the
  application fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"Attacker-supplied HTML and script code would run in the context of the affected
  site, potentially allowing the attacker to steal cookie-based authentication credentials or to control how the
  site is rendered to the user. Oother attacks are also possible.");

  script_tag(name:"affected", value:"Axigen Mail Server 6.2.2 is vulnerable. Other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34716");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "6.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Please contact the vendor.");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
