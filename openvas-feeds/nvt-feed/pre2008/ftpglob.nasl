# SPDX-FileCopyrightText: 2001 EMaze
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10821");
  script_version("2024-02-09T14:47:30+0000");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"IAVA", value:"2001-b-0004");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2550");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3581");
  script_cve_id("CVE-2001-0249", "CVE-2001-0550");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 03:06:01 +0000 (Fri, 02 Feb 2024)");
  script_name("FTPD glob Heap Corruption");
  script_category(ACT_MIXED_ATTACK);
  script_family("FTP");
  script_copyright("Copyright (C) 2001 EMaze");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/banner/available");

  script_tag(name:"solution", value:"Contact your vendor for a fix.");

  script_tag(name:"summary", value:"The FTPD glob vulnerability manifests itself in handling of the glob command.
  The problem is not a typical buffer overflow or format string vulnerability,
  but a combination of two bugs: an implementation of the glob command that does not
  properly return an error condition when interpreting the string '~{',
  and then frees memory which may contain user supplied data. This
  vulnerability is potentially exploitable by any user who is able to log in to
  a vulnerable server, including users with anonymous access. If successful, an
  attacker may be able to execute arbitrary code with the privileges of FTPD,
  typically root.");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
password = kb_creds["pass"];

port = ftp_get_port(default:21);

if(safe_checks())
  login = 0;

if(login) {

  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  if (ftp_authenticate(socket:soc, user:login, pass:password)){

    bracket = raw_string(0x7B);
    c = string("CWD ~", bracket, "\r\n");
    d = string("CWD ~*", bracket, "\r\n");

    send(socket:soc, data:c);
    b = ftp_recv_line(socket:soc);

    send(socket:soc, data:d);
    e = ftp_recv_line(socket:soc);

    # Buggy version. no known exploits
    buggy = string("You seem to be running an FTP server which is vulnerable to the 'glob heap corruption'\n",
                   "flaw, but which can not be exploited on this server.");

    # Vulnerable version. Working exploit has been written
    vuln = string("You seem to be running an FTP server which is vulnerable to the 'glob heap corruption'\n",
                  "flaw, which is known to be exploitable remotely against this server. An attacker may use \n",
                  "this flaw to execute arbitrary commands on this host.");

    # linux/bsd: wuftpd, beroftpd
    # solaris: ftpd

    if(!b || !e) {
      security_message(port:port, data:vuln);
      exit(0);
    }

    ftp_close(socket:soc);

    # Freebsd / Openbsd command successful.
    # buggy version
    if("250 CWD command successful" >< b || "250 CWD command successful" >< e) {
      security_message(port:port, data:buggy);
      exit(0);
    }

    # Netbsd vulnerable
    if(":" >< b || ":" >< e) {
      security_message(port:port, data:vuln);
      exit(0);
    }

    # Aix buggy
    if("550 Unknown user name after ~" >< b ||"550 Unknown user name after ~" >< e) {
      security_message(port:port, data:buggy);
      exit(0);
    }

    # Mac OS X Darwin buggy
    if("550 ~: No such file or directory" >< b || "550 ~: No such file or directory" >< e) {
      security_message(port:port, data:buggy);
      exit(0);
    }
    exit(0);
  }
  ftp_close(socket:soc);
}

if (os_host_runs(".*FreeBSD (4\.[5-9]|5\..*).*") == "yes") exit(0);

# We weren't able to login into the ftp server. Check the banner instead
banner = ftp_get_banner(port:port);
if(!banner)
  exit(0);

# FTP server 4.1 (aix/ultrix), 1.1. (hp-ux), 6.00 (darwin), 6.00LS (freebsd)
# wu-ftpd 2.6.1-20 is not vulnerable
if(egrep(pattern:".*wu-2\.6\.1-[2-9][0-9].*", string:banner))exit(0);

if ( "PHNE_27765" >< banner || "PHNE_29461" >< banner ||
     "PHNE_30432" >< banner || "PHNE_31931" >< banner ||
     "PHNE_30990" >< banner ) exit(0);

if ( egrep(pattern:".*wu-([01]|(2\.([0-5][^0-9]|6\.[01]))).*", string:banner) ||
     egrep(pattern:".*BeroFTPD.*", string:banner) ||
     egrep(pattern:".*NetBSD-ftpd (199[0-9]|200[01]).*", string:banner) ||
     egrep(pattern:".*Digital UNIX Version [0-5]\..*", string:banner) ||
     egrep(pattern:".*SunOS [0-5]\.[0-8].*", string:banner) ||
     egrep(pattern:".*FTP server.*Version (1\.[01]\.|4\.1|6\.00|6\.00LS).*", string:banner) ||
     egrep(pattern:".*FTP server .SRPftp 1\.[0-3].*", string:banner)) {
  banvuln = string("You seem to be running an FTP server which is vulnerable to the\n", "'glob heap corruption' flaw.");
  security_message(port:port, data:banvuln);
  exit(0);
}
