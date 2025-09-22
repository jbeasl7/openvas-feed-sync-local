# SPDX-FileCopyrightText: 2002 Jason Lidow <jason@brandx.net>
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11005");
  script_version("2024-06-07T05:05:42+0000");
  script_cve_id("CVE-2001-0189", "CVE-2002-0897");
  script_tag(name:"last_modification", value:"2024-06-07 05:05:42 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("LocalWeb2000 <= 2.1.0 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Jason Lidow <jason@brandx.net>");
  script_family("Remote file access");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("LocalWEB2000/banner");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210208165641/http://www.securityfocus.com/bid/2268");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210208165641/http://www.securityfocus.com/bid/4820");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210208165641/http://www.securityfocus.com/bid/7947");

  script_tag(name:"summary", value:"LocalWeb2000 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if the product is available on the target host.");

  script_tag(name:"insight", value:"Version 2.1.0 of LocalWeb2000 allows an attacker to view
  protected files on the host's computer.

  Example: vulnerableserver.com/./protectedfolder/protectedfile.htm

  It may also disclose the NetBIOS name of the remote host when it receives malformed directory
  requests.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port:port);

if(banner && egrep(pattern:"^Server\s*:\s*LocalWEB2000", string:banner, icase:TRUE)) {
  security_message(port:port);
  exit(0);
}

exit(99);
