# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:redhat:jboss_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142595");
  script_version("2024-01-09T05:06:46+0000");
  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2019-07-12 06:01:03 +0000 (Fri, 12 Jul 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2007-1036");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Red Hat JBoss Application Server (AS) Console and Web Management Misconfiguration Vulnerability - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_red_hat_jboss_prds_http_detect.nasl", "gb_red_hat_jboss_eap_http_detect.nasl",
                      "sw_redhat_wildfly_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("redhat/jboss/prds/http/detected");

  script_tag(name:"summary", value:"The default configuration of Red Hat JBoss Application Server
  (AS) does not restrict access to the console and web management interfaces, which allows remote
  attackers to bypass authentication and gain administrative access via direct requests.");

  script_tag(name:"vuldetect", value:"Checks via crafted HTTP GET requests if the jmx-console or
  web-console is accessible without authentication.");

  script_tag(name:"solution", value:"As stated by Red Hat, the JBoss AS console manager should
  always be secured prior to deployment, as directed in the JBoss Application Server Guide and
  release notes. By default, the JBoss AS installer gives users the ability to password protect the
  console manager. If the user did not use the installer, the raw JBoss services will be in a
  completely unconfigured state and these steps should be performed manually. See the referenced
  advisories for mitigation steps.");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/632656/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/460597/100/0/threaded");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

cpe_list = make_list("cpe:/a:redhat:jboss_application_server",
                     "cpe:/a:redhat:jboss_enterprise_application_platform",
                     "cpe:/a:redhat:jboss_wildfly_application_server");

if (!infos = get_app_port_from_list(cpe_list: cpe_list, service: "www", first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if (!dir = get_app_location(cpe: cpe, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/web-console/ServerInfo.jsp";

if (http_vuln_check(port: port, url: url, check_header: TRUE, extra_check: "Management Console",
                    pattern: "<title>JBoss Management Console - Server Information</title>", usecache: TRUE)) {
  report = "It was possible to access the JBoss Web Console at " +
           http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

url = dir + "/jmx-console/";

if (http_vuln_check(port: port, url: url, pattern: "<title>JBoss JMX Management Console",
                    check_header: TRUE, usecache: TRUE)) {
  if (report)
    report += '\n\n';
  report += "It was possible to access the JBoss JMX Management Console at " +
            http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

if (report) {
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
