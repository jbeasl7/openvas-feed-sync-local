# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103222");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-24 15:44:33 +0200 (Wed, 24 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress User IDs and User Names Disclosure");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_xref(name:"URL", value:"http://www.talsoft.com.ar/index.php/research/security-advisories/wordpress-user-id-and-user-name-disclosure");

  script_tag(name:"summary", value:"WordPress platforms use a parameter called `author'. This parameter
  accepts integer values and represents the `User ID' of users in the
  web site. For example: http://www.example.com/?author=1");

  script_tag(name:"insight", value:"The problems found are:

  1. User ID values are generated consecutively.

  2. When a valid User ID is found, WordPress redirects to a web page
  with the name of the author.");

  script_tag(name:"impact", value:"These problems trigger the following attack vectors:

  1. The query response discloses whether the User ID is enabled.

  2. The query response leaks (by redirection) the User Name
  corresponding with that User ID.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

for(i = 1; i < 25; i++) {

  url = string(dir, "/?author=", i);
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(!buf)
    continue;

  if(buf =~ "^HTTP/1\.[01] 301")  {

    lines = split(buf);

    foreach line (lines) {

      if(egrep(pattern:"Location:", string:line)) {

        username = eregmatch(pattern:"Location: http://.*/.*/([^/]+)/", string:line);

        if(!isnull(username[1])) {
          usernames[i] = string("Discovered username '", username[1], "' with id '", i, " via URL " + http_report_vuln_url(port:port, url:url, url_only:TRUE) + '\n');
        }
      }
    }
  }
}

if(usernames) {

  foreach name (usernames) {
    userstr += string(name);
  }
  userstr = chomp(userstr);
  rep = string("The following user names were revealed in id range 1-25.\n\n");
  security_message(port:port, data:chomp(rep + userstr));
  exit(0);
}

exit(99);
