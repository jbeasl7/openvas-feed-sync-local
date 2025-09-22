# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:shoretel:shoreware_director";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103814");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("ShoreTel ShoreWare Director Remote Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63019");

  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-10-16 12:02:38 +0200 (Wed, 16 Oct 2013)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_shoreware_director_detect.nasl");
  script_mandatory_keys("ShoreWare_Director/installed");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass security restrictions to
perform unauthorized actions or cause a denial-of-service condition.");
  script_tag(name:"vuldetect", value:"Check the Build version.");
  script_tag(name:"insight", value:"By default, the /ShorewareDirector directory is available via
anonymous FTP, unrestricted, and with read-write access.  It is
vulnerable to:

  - A Denial of Service (DoS) filling up the disk with arbitrary files.
If the directory resides on the C: drive, it could make the entire
server unavailable.  Otherwise, it could prevent administrators from
changing menu prompts or other system functions utilizing the same
disk.

  - Unauthenticated changes and deletion of menu prompts actively being
used by the system.  Deleting an actively used file will cause the
system to use the default greeting.  An attacker could overwrite an
active prompt (can take hours to refresh from the FTP server though)
that would result in a good laugh and high fives, but also could be
used to convince users to take further action or disclose sensitive
information as a step in a more complex attack.");
  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"ShoreWare Director is prone to a remote security bypass vulnerability.");
  script_tag(name:"affected", value:"ShoreWare Director 18.61.7500.0 is vulnerable. Other versions may also
be affected.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if(!build = get_kb_item("www/" + port + "/ShoreWare_Director/build"))
  exit(0);

if(version_is_less(version: build, test_version: "18.61.7500.0")) {
  report = report_fixed_ver(installed_version:build, fixed_version:"18.61.7500.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
