# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105353");
  script_cve_id("CVE-2015-6290");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Web Security Appliance Malformed HTTP Response Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuw10426");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker could exploit this vulnerability to cause a DoS condition on the targeted device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to the improper handling of a malformed HTTP server responses. An unauthenticated, remote attacker with a privileged network position could
exploit the vulnerability by conducting a man-in-the-middle (MitM) attack and supplying malformed HTTP server responses to the vulnerable device. A successful exploit could allow the attacker to cause
the device to improperly close TCP connections and fail to free memory resources, resulting in a partial DoS condition.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"Cisco Web Security Appliance contains a vulnerability that could allow an unauthenticated, remote attacker to cause a denial of service condition. Updates are not available.");
  script_tag(name:"affected", value:"Cisco WSA version 8.0.7-151");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-11 13:28:16 +0200 (Fri, 11 Sep 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/installed");
  exit(0);
}

include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

if( vers == "8.0.7-151" )
{
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     See vendor advisory';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

