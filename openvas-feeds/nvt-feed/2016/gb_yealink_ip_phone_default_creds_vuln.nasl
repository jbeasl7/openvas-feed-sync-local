# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:yealink:voip_phone_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106326");
  script_version("2023-08-24T05:06:01+0000");
  script_tag(name:"last_modification", value:"2023-08-24 05:06:01 +0000 (Thu, 24 Aug 2023)");
  script_tag(name:"creation_date", value:"2016-10-05 08:36:01 +0700 (Wed, 05 Oct 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Yealink IP Phone Default Credentials");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_yealink_ip_phone_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("yealink/ipphone/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The Yealink IP Phone has default credentials set.");

  script_tag(name:"impact", value:"A remote attacker may gain sensitive information or reconfigure the Yealink
  IP Phone.");

  script_tag(name:"solution", value:"Change the password");

  script_tag(name:"vuldetect", value:"Try to login with the default credentials.");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = '/servlet?p=login&q=login';
data = 'username=admin&pwd=admin&jumpto=status&acc=';

req = http_post_put_req(port: port, url: url, data: data,
                        add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));

res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

if (res !~ "HTTP/1\.. 401" && "Location: /servlet?p=status&q=load" >< res) {
  report = "It was possible to login with user 'admin' and password 'admin'.";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
