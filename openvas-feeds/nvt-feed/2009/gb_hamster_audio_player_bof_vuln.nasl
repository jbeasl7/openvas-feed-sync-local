# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ondanera.net:hamster_audio_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900693");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2550");
  script_name("Hamster Audio Player Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_hamster_audio_player_detect.nasl");
  script_mandatory_keys("hamster/audio-player/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35825");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9172");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51732");

  script_tag(name:"impact", value:"Successful exploitation allows the attacker to execute arbitrary
  code on the system or cause the application to crash.");

  script_tag(name:"affected", value:"Hamster Audio Player 0.3a and prior on Windows.");

  script_tag(name:"insight", value:"This flaw is due to improper bounds checking when processing
  .m3u files and can be exploited by persuading a victim to open a specially-crafted .m3u or .hpl
  playlist file containing an overly long string.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Hamster Audio player is prone to Stack Overflow Vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"0.3a")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
