# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100073");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2009-03-23 19:32:33 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-30 20:58:00 +0000 (Tue, 30 Jul 2019)");
  script_cve_id("CVE-1999-0512", "CVE-2002-1278", "CVE-2003-0285", "CVE-2003-0316", "CVE-2005-0431",
                "CVE-2005-2857", "CVE-2006-0977", "CVE-2019-14403");
  script_name("Mail relaying");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("SMTP problems");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl", "smtp_settings.nasl", "global_settings.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);
  script_mandatory_keys("smtp/banner/available", "keys/is_public_addr");

  script_tag(name:"summary", value:"The remote SMTP server is insufficiently protected against mail
  relaying.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted SMTP requests and checks the responses.

  Note:

  This VT is only reporting a vulnerability if the target system / service is accessible from a
  public WAN (Internet) / public LAN.

  A configuration option 'Network type' to define if a scanned network should be seen as a public
  LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"impact", value:"This means that spammers might be able to use your mail server to
  send their mails to the world.");

  script_tag(name:"solution", value:"Improve the configuration of your SMTP server so that your SMTP
  server cannot be used as a relay any more.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("network_func.inc");

debug = FALSE;

if(!is_public_addr()) {
  if(debug) display('DEBUG: Target-IP "' + get_host_ip() + '" is not a public address. Exiting...');
  exit(0);
}

domain = get_3rdparty_domain();
src_name = this_host_name();
vtstrings = get_vt_strings();
FROM = string(vtstrings["lowercase"], '@', src_name);
TO = string(vtstrings["lowercase"], '@', domain);
target = get_host_name();

port = smtp_get_port(default:25);
if(get_kb_item("smtp/" + port + "/qmail/detected")) {
  if(debug) display('DEBUG: QMail detected. Exiting...');
  exit(0);
}

if(smtp_get_is_marked_wrapped(port:port)) {
  if(debug) display('DEBUG: SMTP service is marked as "wrapped". Exiting...');
  exit(0);
}

helo_name = smtp_get_helo_from_kb(port:port);
soc = smtp_open(port:port, data:helo_name, send_helo:TRUE, code:"250");
if(!soc) {
  if(debug && __smtp_open_helo_ehlo_sent && __smtp_open_helo_ehlo_recv) display('DEBUG: SMTP service is not accepting our HELO:\n\n' + __smtp_open_helo_ehlo_sent + '\n\nAnswer received:\n\n' + __smtp_open_helo_ehlo_recv + '\n\n Exiting...');
  else if(debug && __smtp_open_helo_ehlo_sent) display('DEBUG: SMTP service is not accepting our HELO:\n\n' + __smtp_open_helo_ehlo_sent + '\n\nNo answer received. Exiting...');
  else if(debug) display('DEBUG: Failed to open a connection to the SMTP service. Exiting...');
  exit(0);
}

if(__smtp_open_banner_recv) {
  if(debug) display('DEBUG: SMTP banner received:\n\n' + __smtp_open_banner_recv);
  bannerres = __smtp_open_banner_recv;
} else {
  if(debug) display('DEBUG: NO SMTP banner received.');
  bannerres = "No SMTP banner received";
}

if(debug && __smtp_open_helo_ehlo_sent) display('DEBUG: SMTP HELO sent:\n\n' + __smtp_open_helo_ehlo_sent);
if(debug && __smtp_open_helo_ehlo_recv) display('DEBUG: SMTP HELO answer received:\n\n' + __smtp_open_helo_ehlo_recv);

mf = strcat('MAIL FROM: <', FROM , '>\r\n');
if(debug) display('DEBUG: SMTP request sent:\n\n' + str_replace(string:mf, find:'\r\n', replace:"<CR><LF>"));
send(socket:soc, data:mf);
l = smtp_recv_line(socket:soc);
if(!l || l =~ '^5[0-9]{2}') {
  if(debug && l) display('DEBUG: Unexpected SMTP response received:\n\n' + str_replace(string:l, find:'\r\n', replace:"<CR><LF>") + '\n\nExpecting response not matching the following regex: "^5[0-9]{2}". Exiting...');
  else if(debug) display('DEBUG: No (valid) SMTP response received. Exiting...');
  smtp_close(socket:soc, check_data:l);
  exit(0);
}
mfres = l;
if(debug) display('DEBUG: SMTP response received:\n\n' + str_replace(string:mfres, find:'\r\n', replace:"<CR><LF>"));

rt = strcat('RCPT TO: <', TO , '>\r\n');
if(debug) display('DEBUG: SMTP request sent:\n\n' + str_replace(string:rt, find:'\r\n', replace:"<CR><LF>"));
send(socket:soc, data:rt);
l = smtp_recv_line(socket:soc);
if(!l || l !~ '^2[0-9]{2}[ -].+') {
  if(debug && l) display('DEBUG: Unexpected SMTP response received:\n\n' + str_replace(string:l, find:'\r\n', replace:"<CR><LF>") + '\n\nExpecting regex: "^2[0-9]{2}[ -].+". Exiting...');
  else if(debug) display('DEBUG: No (valid) SMTP response received. Exiting...');
  smtp_close(socket:soc, check_data:l);
  exit(0);
}
rtres = l;
if(debug) display('DEBUG: SMTP response received:\n\n' + str_replace(string:rtres, find:'\r\n', replace:"<CR><LF>"));

data = string("data\r\n");
if(debug) display('DEBUG: SMTP request sent:\n\n' + str_replace(string:data, find:'\r\n', replace:"<CR><LF>"));
send(socket:soc, data:data);
l = smtp_recv_line(socket:soc);
if(!l || l !~ '^3[0-9]{2}[ -].+') {
  if(debug && l) display('DEBUG: Unexpected SMTP response received:\n\n' + str_replace(string:l, find:'\r\n', replace:"<CR><LF>") + '\n\nExpecting regex: "^3[0-9]{2}[ -].+". Exiting...');
  else if(debug) display('DEBUG: No (valid) SMTP response received. Exiting...');
  smtp_close(socket:soc, check_data:l);
  exit(0);
}
datares = l;
if(debug) display('DEBUG: SMTP response received:\n\n' + str_replace(string:datares, find:'\r\n', replace:"<CR><LF>"));

dc  = string("Subject: ", vtstrings["default"], "-Relay-Test\r\n");
dc += string("To: ", vtstrings["default"], "-Relay-Test <", TO, ">\r\n");
dc += string("From: ", vtstrings["default"], "-Relay-Test <", FROM, ">\r\n\r\n");
dc += string("This is a ", vtstrings["default"], "-Relay-Test to test the mail server at:\r\n\r\n", target, "\r\n\r\nif it is configured as an open mail relay.\r\n\r\n");
dc += string("If you have received this message please forward it to the administrator of this mail server and ask to protect it against mail relaying.");
dc += string("\r\n.\r\n");
send(socket:soc, data:dc);
l = smtp_recv_line(socket:soc);
smtp_close(socket:soc, check_data:l);

if(l && l =~ '^250[ -].+') {
  if(debug) display('DEBUG: SMTP response received:\n\n' + str_replace(string:l, find:'\r\n', replace:"<CR><LF>"));
  report  = 'SMTP banner:\n\n';
  report += bannerres + '\n\n';
  report += 'The scanner was able to relay mail by sending the following sequences:\n\n';
  report += 'Request: ' + __smtp_open_helo_ehlo_sent;
  report += '\nAnswer:  ' + __smtp_open_helo_ehlo_recv;
  report += '\nRequest: ' + str_replace(string:mf, find:'\r\n', replace:"<CR><LF>");
  report += '\nAnswer:  ' + str_replace(string:mfres, find:'\r\n', replace:"<CR><LF>");
  report += '\nRequest: ' + str_replace(string:rt, find:'\r\n', replace:"<CR><LF>");
  report += '\nAnswer:  ' + str_replace(string:rtres, find:'\r\n', replace:"<CR><LF>");
  report += '\nRequest: ' + str_replace(string:data, find:'\r\n', replace:"<CR><LF>");
  report += '\nAnswer:  ' + str_replace(string:datares, find:'\r\n', replace:"<CR><LF>");
  report += '\nRequest: ' + str_replace(string:dc, find:'\r\n', replace:"<CR><LF>");
  report += '\nAnswer:  ' + str_replace(string:l, find:'\r\n', replace:"<CR><LF>");
  security_message(port:port, data:report);
  set_kb_item(name:"smtp/" + port + "/spam", value:TRUE);
  set_kb_item(name:"smtp/spam", value:TRUE);
  exit(0);
} else if(l && l !~ '^250[ -].+') {
  if(debug && l) display('DEBUG: Unexpected SMTP response received:\n\n' + str_replace(string:l, find:'\r\n', replace:"<CR><LF>") + '\n\nExpecting regex: "250[ -].+". Exiting...');
} else {
  if(debug) display('DEBUG: No (valid) SMTP response received. Exiting...');
}

exit(99);
