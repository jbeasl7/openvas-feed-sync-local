# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140533");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-11-24 10:59:47 +0700 (Fri, 24 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-12 15:54:00 +0000 (Tue, 12 Dec 2017)");

  script_cve_id("CVE-2017-8860", "CVE-2017-8861", "CVE-2017-8862", "CVE-2017-8863", "CVE-2017-8864");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Cohu 3960HD Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Cohu/banner");

  script_tag(name:"summary", value:"Cohu 3960HD Series IP cameras are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Cohu 3960HD Series IP cameras are prone to multiple vulnerabilities:

  - Information exposure through directory listing (CVE-2017-8860)

  - Cleartext transmission of sensitive information

  - Missing authentication for critical function (CVE-2017-8861)

  - Unrestricted upload of file with dangerous type (CVE-2017-8862)

  - Information exposure through source code (CVE-2017-8863)

  - Client side enforcement of server side security (CVE-2017-8864)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://bneg.io/2017/05/12/vulnerabilities-in-cohu-3960hd/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "//";

if (http_vuln_check(port: port, url: url, pattern: "Directory listing of", check_header: TRUE, usecache: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
