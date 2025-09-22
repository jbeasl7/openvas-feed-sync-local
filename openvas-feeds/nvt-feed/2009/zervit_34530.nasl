# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100199");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-05-14 12:53:07 +0200 (Thu, 14 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1353");
  script_name("Zervit Webserver 0.2 - 0.4 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Zervit/banner");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121190258/https://www.securityfocus.com/bid/34530/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210127233049/http://www.securityfocus.com/bid/34570");

  script_tag(name:"summary", value:"According to its version number, the remote version of Zervit
  HTTP server is prone to a remote buffer overflow vulnerability and to a directory traversal
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit the remote buffer-overflow issue to
  execute arbitrary code within the context of the affected application. Failed exploit attempts
  will result in a denial-of-service condition.

  Exploiting the directory-traversal issue will allow an attacker to view arbitrary local files
  within the context of the webserver. Information harvested may aid in launching further
  attacks.");

  script_tag(name:"affected", value:"Zervit 0.2, 0.3 and 0.4 are known to be vulnerable. Other
  versions may also be affected.");

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
include("version_func.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port:port);

if(!banner || !egrep(pattern:"[Ss]erver\s*:\s*Zervit ([0-9.]+)", string:banner))
  exit(0);

version = eregmatch(pattern:"Zervit ([0-9.]+)", string:banner);

if(version[1] =~ "0\.[2-4]") {
  report = report_fixed_ver(installed_version:version[1], fixed_version:"None");
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
