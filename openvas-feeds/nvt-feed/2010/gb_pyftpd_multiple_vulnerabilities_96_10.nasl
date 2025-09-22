# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100679");
  script_version("2024-02-14T05:07:39+0000");
  script_tag(name:"last_modification", value:"2024-02-14 05:07:39 +0000 (Wed, 14 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-06-15 13:44:31 +0200 (Tue, 15 Jun 2010)");
  script_cve_id("CVE-2010-2072", "CVE-2010-2073");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 16:44:33 +0000 (Tue, 13 Feb 2024)");

  script_name("pyftpd Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40839");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40842");
  script_xref(name:"URL", value:"http://comments.gmane.org/gmane.comp.security.oss.general/3038");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=585776");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("FTP");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 2121);
  script_mandatory_keys("ftp/pyftpdlib/detected");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"pyftpd is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"1.

  pyftpd is prone to multiple default-account vulnerabilities. These
  issues stem from a design flaw that makes several accounts available
  to remote attackers.

  Successful exploits allow remote attackers to gain unauthorized access
  to a vulnerable application.

  2.

  pyftpd creates temporary files in an insecure manner.

  An attacker with local access could potentially exploit this issue to
  perform symbolic-link attacks, overwriting arbitrary files in the
  context of the affected application.

  Successfully mounting a symlink attack may allow the attacker to
  delete or corrupt sensitive files, which may result in a denial of
  service. Other attacks may also be possible.");

  script_tag(name:"affected", value:"pyftpd prior to 0.8.5 are affected.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:2121);
banner = ftp_get_banner(port:ftpPort);
if(! banner || "pyftpd" >!< tolower(banner))
  exit(0);

users = make_list("test", "user", "huddel");
success = 0;
failed = 0;

foreach user (users) {

  soc1 = open_sock_tcp(ftpPort);
  if(!soc1)
    exit(0);

  login_details = ftp_log_in(socket:soc1, user:user, pass:user);

  if(login_details)
  {
    success++;
    ftp_close(socket:soc1);
  } else {
    failed++;
    ftp_close(socket:soc1);
  }
}

if(success == 2 && failed == 1) {
  security_message(port:ftpPort);
  exit(0);
}

exit(99);
