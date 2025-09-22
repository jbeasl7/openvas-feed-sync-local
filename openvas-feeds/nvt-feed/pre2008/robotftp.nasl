# SPDX-FileCopyrightText: 2004 Audun Larsen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12082");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9729");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RobotFTP DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2004 Audun Larsen");
  script_family("Denial of Service");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/robot/ftp/detected");

  script_tag(name:"summary", value:"RobotFTP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"The issue presents itself when certain commands are sent to the service,
  before authentication is negotiated.");

  script_tag(name:"affected", value:"The following versions of RobotFTP are vulnerable:

  RobotFTP RobotFTP Server 1.0

  RobotFTP RobotFTP Server 2.0 Beta 1

  RobotFTP RobotFTP Server 2.0.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
banner  = ftp_get_banner(port:port);
if ( ! banner ) exit(0);

if ( egrep(pattern:"^220.*RobotFTP", string:banner) )
{
  security_message(port);
  exit(0);
}
