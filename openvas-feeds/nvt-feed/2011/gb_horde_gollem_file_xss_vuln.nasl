# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801870");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_cve_id("CVE-2010-3447");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Horde Gollem 'file' Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://bugs.horde.org/ticket/9191");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41624");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2523");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_horde_gollem_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("horde/gollem/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Horde Gollem versions before 1.1.2.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via the
  'file' parameter to 'view.php', which allows attackers to execute arbitrary
  HTML and script code on the web server.");

  script_tag(name:"solution", value:"Upgrade to Horde Gollem version 1.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Horde Gollem is prone to a cross-site scripting (XSS) vulnerability.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(vers = get_version_from_kb(port:port, app:"gollem"))
{
  if(version_is_less(version:vers, test_version:"1.1.2")){
    report = report_fixed_ver(installed_version:vers, fixed_version:"1.1.2");
    security_message(port: port, data: report);
  }
}
