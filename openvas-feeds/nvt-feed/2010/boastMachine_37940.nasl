# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kailash_nadh:boastmachine";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100461");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-25 18:49:48 +0100 (Mon, 25 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("boastMachine Arbitrary File Upload Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37940");
  script_xref(name:"URL", value:"http://boastology.com/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("boastMachine_detect.nasl");
  script_mandatory_keys("boastmachine/installed");

  script_tag(name:"summary", value:"boastMachine is prone to a vulnerability that lets attackers upload arbitrary
  files because the application fails to adequately sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to upload arbitrary code and run it in the context of the webserver
  process. This may facilitate unauthorized access or privilege escalation. Other attacks are also possible.");

  script_tag(name:"affected", value:"boastMachine 3.1 is affected. Other versions may be vulnerable as well.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);