# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:etcd:etcd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140888");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-03-27 08:55:55 +0700 (Tue, 27 Mar 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("etcd Information Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_etcd_http_detect.nasl");
  script_mandatory_keys("etcd/http/detected");
  script_require_ports("Services/www", 2379);

  script_tag(name:"summary", value:"etcd is prone to an information disclosure vulnerability if no
  authentication is enabled. An attacker may read all stored key values which might contain
  sensitive information like passwords.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An unauthenticated attacker may gather sensitive information
  which could lead to further attacks.");

  script_tag(name:"solution", value:"Enable authentication as referenced in the advisory.");

  script_xref(name:"URL", value:"https://coreos.com/etcd/docs/latest/v2/authentication.html");
  script_xref(name:"URL", value:"https://elweb.co/the-security-footgun-in-etcd/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/v2/keys/?recursive=true";
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && '{"action":"get"' >< res) {
  expert_info = 'Response:\n' + res;
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report, expert_info: expert_info);
  exit(0);
}

exit(99);
