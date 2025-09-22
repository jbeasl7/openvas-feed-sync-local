# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800822");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-6840", "CVE-2006-2666");
  script_name("V-webmail Multiple PHP Remote File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/1827");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30164");
  script_xref(name:"URL", value:"http://secunia.com/advisories/20297");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/0807-exploits/vwebmail-rfi.txt");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_v-webmail_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("v-webmail/detected");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker to execute
  arbitrary PHP code via a URL in the CONFIG[pear_dir] or CONFIG[includes]
  parameters when register_globals is enabled.");

  script_tag(name:"affected", value:"V-webmail version 1.6.4 and prior");

  script_tag(name:"insight", value:"The flaws are due to error in 'CONFIG[pear_dir]' parameter to
  Mail/RFC822.php, Net/Socket.php, XML/Parser.php, XML/Tree.php, Mail/mimeDecode.php,
  Log.php, Console/Getopt.php, System.php, and File.php in includes/pear/ directory
  and also in includes/cachedConfig.php, includes/mailaccess/pop3.php, and
  includes/prepend.php files, and error exists in 'CONFIG[includes]' parameter
  to prepend.php and email.list.search.php in includes/.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"V-webmail is prone to Multiple PHP Remote File Inclusion vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

vwmailPort = http_get_port(default:80);

vwmailVer = get_kb_item("www/" + vwmailPort + "/V-webmail");
vwmailVer = eregmatch(pattern:"^(.+) under (/.*)$", string:vwmailVer);

if(vwmailVer[2] != NULL && (!safe_checks()))
{
  req = http_get(item:vwmailVer[2] + "/includes/mailaccess/pop3.php" +
                                        "?CONFIG[pear_dir]=[SHELL]",
                    port:vwmailPort);
  res = http_send_recv(data:req, port:vwmailPort);
  if("SHELL" >!< res)
  {
    req = http_get(item:vwmailVer[2] + "/includes/prepend.php?CONFIG[includes]=[SHELL]", port:vwmailPort);
    res = http_send_recv(data:req, port:vwmailPort);
  }
  if("SHELL" >< res && egrep(pattern:"^HTTP/1\.[01] 200", string:res))
  {
    security_message(vwmailPort);
    exit(0);
  }
}

if(vwmailVer[1] != NULL)
{
  if(version_is_less_equal(version:vwmailVer[1], test_version:"1.6.4"))
  {
    security_message(vwmailPort);
    exit(0);
  }
}
