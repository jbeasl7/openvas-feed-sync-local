# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elitecms:elitecms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100711");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-07-13 12:45:31 +0200 (Tue, 13 Jul 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("eliteCMS Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41537");
  script_xref(name:"URL", value:"http://elitecms.elite-graphix.net/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("eliteCMS_detect.nasl");
  script_mandatory_keys("elitecms/installed");

  script_tag(name:"summary", value:"eliteCMS is prone to multiple cross-site scripting vulnerabilities because it
fails to properly sanitize user-supplied input before using it in dynamically generated content.

An attacker may leverage these issues to execute arbitrary script code in the browser of an unsuspecting user in
the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and
launch other attacks.

eliteCMS 1.01 is vulnerable, other versions may also be affected.");

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

if (version_is_equal(version: version, test_version: "1.01")) {
  security_message(port:port);
  exit(0);
}

exit(0);
