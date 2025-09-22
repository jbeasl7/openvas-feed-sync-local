# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:composr:cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107215");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-06-13 11:59:56 +0200 (Tue, 13 Jun 2017)");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Composr CMS v10.0.0 XSS Vulnerability");

  script_tag(name:"summary", value:"Composr CMS is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is located in the 'Error Exception' of the 'Delete File' function. The remote attacker is
  able to inject own malicious code via GET method request in the 'file' parameter to provoke an execution. The injection point is the 'file'
  parameter and the execution point occurs in the error exception that displays the content to confirm a delete.");

  script_tag(name:"impact", value:"Successful exploitation of the vulnerability results in session hijacking, non-persistent phishing attacks, non-persistent external redirects to
  malicious sources and non-persistent manipulation of affected or connected application modules.");

  script_tag(name:"affected", value:"Composr CMS version 10.0.0.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Jun/15");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_composr_cms_detect.nasl");
  script_mandatory_keys("composr_cms/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!ver = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_equal(version: ver, test_version: "10.0.0"))
{
  report = report_fixed_ver(installed_version: ver, fixed_version: "WillNotFix");
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
