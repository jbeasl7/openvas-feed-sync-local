# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805472");
  script_version("2023-06-22T13:00:03+0000");
  script_cve_id("CVE-2015-0995", "CVE-2015-0994", "CVE-2015-0993", "CVE-2015-0992",
                "CVE-2015-0991", "CVE-2015-0976");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-06-22 13:00:03 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2015-04-11 14:20:21 +0530 (Sat, 11 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Inductive Automation Ignition < 7.7.4 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Inductive Automation Ignition is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if a vulnerable
  version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exist due to:

  - The MD5 Message-Digest Algorithm does not provide enough collision resistance
    when hashing keys.

  - A flaw in Inductive Automation Ignition that is triggered when resetting the
    session ID parameter via a HTTP request.

  - A flaw in the web interface that is due to a missing session termination once
    a user logs out.

  - A flaw in application that is due to the program storing OPC server credentials
    in plaintext.

  - A flaw in application that is triggered when an unhandled exception occurs,
    which can cause an error or warning message.

  - The application does not validate input before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information, hijack an active
  session, bypass the anti-bruteforce mechanism, create malicious applications
  or conduct other spoofing attacks, and create a specially crafted request that
  would execute arbitrary script code in a user's browser session.");

  script_tag(name:"affected", value:"Inductive Automation Ignition version 7.7.2");

  script_tag(name:"solution", value:"Upgrade to Inductive Automation Ignition
  version 7.7.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-15-090-01");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73475");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73474");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73473");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73471");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73468");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8088);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:8088);

url = "/main/web/status/";
buf = http_get_cache(item:url, port:port);

if(buf =~ "Server\s*:\s*Jetty" || buf =~ "^HTTP/1\.[01] 302") {

  # nb: Grab a fresh cookie
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  cookie = eregmatch(pattern:"JSESSIONID=([0-9a-zA-Z]+);", string:buf);
  if(!cookie[1])
    exit(0);

  url = "/main/web/status/;jsessionid=" + cookie[1] + "?0";
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(">Ignition Gateway<" >< buf && ">Ignition by Inductive Automation" >< buf) {

    ignitionVer = eregmatch(pattern:'>Ignition Gateway.*detail..([0-9.]+) ', string:buf);
    if (ignitionVer[1]) {
      if(version_is_equal(version:ignitionVer[1], test_version:"7.7.2")) {
        report = report_fixed_ver(installed_version:ignitionVer[1], fixed_version:"7.7.4");
        security_message(data:report, port:port);
        exit(0);
      }
    }
  }
}
