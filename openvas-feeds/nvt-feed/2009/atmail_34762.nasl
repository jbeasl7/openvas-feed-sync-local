# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atmail:atmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100238");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-22 19:53:45 +0200 (Wed, 22 Jul 2009)");
  script_cve_id("CVE-2009-2455");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Atmail 'admin.php' Cross-Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34762");
  script_xref(name:"URL", value:"http://www.atmail.com");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("atmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Atmail/installed");

  script_tag(name:"summary", value:"AtMail is prone to multiple cross-site scripting vulnerabilities because
  the application fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary script code in
  the browser of an unsuspecting user in the context of the affected site. This may help the attacker steal
  cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"The issues affect Atmail 5.61. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less_equal(version: vers, test_version: "5.61")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);