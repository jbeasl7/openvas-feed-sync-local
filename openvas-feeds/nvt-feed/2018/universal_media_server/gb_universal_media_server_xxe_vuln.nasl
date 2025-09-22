# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:universal_media_server:universal_media_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141352");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-08-07 08:45:28 +0700 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-17 15:04:00 +0000 (Wed, 17 Oct 2018)");

  script_cve_id("CVE-2018-13416");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Universal Media Server XXE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_universal_media_server_detect.nasl");
  script_mandatory_keys("universal_media_server/installed");

  script_tag(name:"summary", value:"In Universal Media Server (UMS), the XML parsing engine for
  SSDP/UPnP functionality is vulnerable to an XML external entity (XXE) processing attack.");

  script_tag(name:"insight", value:"Remote, unauthenticated attackers can use this vulnerability to:
  Access arbitrary files from the filesystem with the same permission as the user account running
  UMS, Initiate SMB connections to capture a NetNTLM challenge/response and crack to cleartext
  password, or Initiate SMB connections to relay a NetNTLM challenge/response and achieve Remote
  Command Execution in Windows domains.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Universal Media Server version 7.1.0 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/45133/");
  script_xref(name:"URL", value:"https://github.com/UniversalMediaServer/UniversalMediaServer/issues/1522");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "7.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
