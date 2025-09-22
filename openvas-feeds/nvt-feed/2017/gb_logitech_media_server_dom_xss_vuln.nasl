# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:logitech:media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811878");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-15687");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-17 16:13:00 +0000 (Fri, 17 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-10-24 18:15:51 +0530 (Tue, 24 Oct 2017)");
  script_name("Logitech Media Server DOM Based XSS Vulnerability");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_logitech_media_server_consolidation.nasl");
  script_mandatory_keys("logitech/squeezecenter/version");

  script_xref(name:"URL", value:"https://fireshellsecurity.team/assets/pdf/DOM-Based-Cross-Site-Scripting-_XSS_-Logitech-Media-Server.pdf");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43024");

  script_tag(name:"summary", value:"Logitech Media Server is prone to a dom based cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  validation of user supplied input via url.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  users to execute arbitrary script code in the browser of an unsuspecting user
  in the context of the affected site. This may allow the attacker to steal
  cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Logitech Media Server versions 7.7.3,
  7.7.5, 7.9.1, 7.7.2, 7.7.1, 7.7.6 and 7.9.0.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

foreach affected_version (make_list("7.7.3", "7.7.5", "7.9.1", "7.7.2", "7.7.1", "7.7.6", "7.9.0")){
  if(affected_version == vers) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"WillNotFix");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);