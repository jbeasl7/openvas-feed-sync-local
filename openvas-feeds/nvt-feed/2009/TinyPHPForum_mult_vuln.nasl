# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100097");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-04-02 12:09:33 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("TinyPHPForum Multiple Vulnerabilities");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("TinyPHPForum_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tinyphpforum/detected");

  script_tag(name:"summary", value:"TinyPHPForum is prone to a directory traversal vulnerability and to
  an authentication-bypass vulnerability because it fails to
  sufficiently sanitize user-supplied input data.");

  script_tag(name:"impact", value:"A remote attacker can exploit this issue to perform administrative
  functions without requiring authentication or obtain sensitive information that could
  aid in further attacks.");

  script_tag(name:"affected", value:"TinyPHPForum 3.6 and 3.6.1 are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/19281");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34339");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(VER = get_kb_item(string("www/", port, "/TinyPHPForum"))) {
  matches = eregmatch(string:VER, pattern:"^(.+) under (/.*)$");
  if(!isnull(matches)) {
    VER = matches[1];
    if(version_is_less_equal(version:VER, test_version:"3.6.1")) {
       security_message(port:port);
       exit(0);
    }
  }
}

exit(0);
