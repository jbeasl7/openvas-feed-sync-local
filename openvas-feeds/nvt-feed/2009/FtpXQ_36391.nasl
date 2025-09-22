# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100293");
  script_version("2024-07-24T05:06:37+0000");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-10-06 18:45:43 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3545");
  script_name("DataWizard FtpXQ 3.0 Remote DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/ftpxq/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36391");

  script_tag(name:"summary", value:"FtpXQ is prone to a remote denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Remote attackers can cause the affected server to stop responding,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"FtpXQ 3.0 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = ftp_get_port(default:21);

if(!banner = ftp_get_banner(port:port))
  exit(0);

if("FtpXQ" >!< banner)
  exit(0);

version = eregmatch(string:banner, pattern:"Version ([0-9.]+)");
if(!isnull(version[1])) {
  if(version_is_equal(version:version[1], test_version:"3.0")) {
    report = report_fixed_ver(installed_version:version[1], fixed_version:"None");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
