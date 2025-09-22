# SPDX-FileCopyrightText: 2008 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80020");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2007-0563", "CVE-2007-0564");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22184");
  script_xref(name:"OSVDB", value:"32959");
  script_xref(name:"OSVDB", value:"32960");
  script_xref(name:"OSVDB", value:"32961");
  script_name("Symantec Web Security flaws");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("symantec_ws_detection.nasl");
  script_require_ports("Services/www", 8002);
  script_mandatory_keys("SymantecWS/installed");

  script_tag(name:"solution", value:"Upgrade at least to version 3.0.1.85.");

  script_tag(name:"summary", value:"According to its banner, the version of Symantec Web Security
  on the remote host is vulnerable to denial of service and cross-site scripting attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8002 );

version = get_kb_item(string("www/", port, "/SWS"));
if (version) {
  if (ereg(pattern:"^(2\.|3\.0\.(0|1\.([0-9]|[1-7][0-9]|8[0-4])$))", string:version)) {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

exit(0);
