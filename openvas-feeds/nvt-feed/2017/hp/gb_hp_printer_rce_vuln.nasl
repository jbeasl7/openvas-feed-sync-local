# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE_PREFIX = "cpe:/o:hp:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113056");
  script_version("2022-02-15T10:35:00+0000");
  script_tag(name:"last_modification", value:"2022-02-15 10:35:00 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2017-11-23 10:11:12 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-21 15:57:00 +0000 (Wed, 21 Feb 2018)");

  script_cve_id("CVE-2017-2750");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printers RCE Vulnerability (CVE-2017-2750)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Gain a shell remotely");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP Printers are vulnerable to remote code execution
  (RCE) attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw in HP's Digital Signature Validation makes it possible to
  load malicious DLLs onto an HP printer and use it to execute arbitrary code on the machine.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute
  arbitrary code on the target machine.");

  script_tag(name:"affected", value:"Please see the linked vendor advisory for a full list of
  affected devices and firmware versions.");

  script_tag(name:"solution", value:"Update to the fixed firmware version.");

  script_xref(name:"URL", value:"https://foxglovesecurity.com/2017/11/20/a-sheep-in-wolfs-clothing-finding-rce-in-hps-printer-fleet/#arbcode");
  script_xref(name:"URL", value:"https://support.hp.com/nz-en/document/c05839270");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_port_from_cpe_prefix( cpe:CPE_PREFIX, first_cpe_only:TRUE ) )
  exit( 0 );

cpe = infos["cpe"];

if( cpe !~ "^cpe:/o:hp:.+_firmware" )
  exit( 0 );

if( ! version = get_app_version( cpe:cpe, nofork:TRUE ) )
  exit(0);

if( ! model = get_kb_item( "hp/printer/model" ) )
  exit( 0 );

# "Enterprise" and "Managed" often is omitted from the Product Name on the Web-Interface, thus the RegEx [A-Za-z ]*

# All models with a fixed 2405129_000041 version
forty_one = make_list( "LaserJet[A-Za-z ]*Flow MFP M631",
                       "LaserJet[A-Za-z ]*Flow MFP M632",
                       "LaserJet[A-Za-z ]*Flow MFP M633",
                       "LaserJet[A-Za-z ]*MFP M631",
                       "LaserJet[A-Za-z ]*MFP M632",
                       "LaserJet[A-Za-z ]*MFP M633",
                       "LaserJet[A-Za-z ]*Flow MFP E62555",
                       "LaserJet[A-Za-z ]*Flow MFP E62565",
                       "LaserJet[A-Za-z ]*Flow MFP E62575",
                       "LaserJet[A-Za-z ]*MFP E62555",
                       "LaserJet[A-Za-z ]*MFP E62565" );

# All models with a fixed 2405129_000047 version
forty_seven = make_list( "Color LaserJet[A-Za-z ]*M651" );

# All models with a fixed 2405130_000068 version
sixty_eight = make_list( "Color LaserJet[A-Za-z ]*M652",
                         "Color LaserJet[A-Za-z ]*M563",
                         "Color LaserJet[A-Za-z ]*E65050",
                         "Color LaserJet[A-Za-z ]*E65060" );

# All models with a fixed 2405129_000038 version
thirty_eight = make_list( "Color LaserJet[A-Za-z ]*MFP M577" );

# All models with a fixed 2308903_577315 version
three_fifteen = make_list( "Color LaserJet[A-Za-z ]*M552",
                           "Color LaserJet[A-Za-z ]*M553" );

# All models with a fixed 2405129_000042 version
forty_two = make_list( "Color LaserJet M680" );

# All models with a fixed 2405129_000045 version
forty_five = make_list( "LaserJet[A-Za-z ]*500 color MFP M575",
                        "LaserJet[A-Za-z ]*color flow MFP M575" );

# All models with a fixed 2405129_000048 version
forty_eight = make_list( "LaserJet[A-Za-z ]*500 MFP M525",
                         "LaserJet[A-Za-z ]*flow MFP M525" );

# All models with a fixed 2405129_000061 version
sixty_one = make_list( "LaserJet[A-Za-z ]*700 color MFP M775" );

# All models with a fixed 2405129_000057 version
fifty_seven = make_list( "LaserJet[A-Za-z ]*800 color M855" );

# All models with a fixed 2405129_000054 version
fifty_four = make_list( "LaserJet[A-Za-z ]*800 color MFP M880" );

# All models with a fixed 2405129_000060 version
sixty = make_list( "LaserJet[A-Za-z ]*flow M830z MFP" );

# All models with a fixed 2405129_000040 version
forty = make_list( "LaserJet[A-Za-z ]*MFP M630",
                   "LaserJet[A-Za-z ]*Flow MFP M630" );

# All models with a fixed 2405129_000039 version
thirty_nine = make_list( "LaserJet[A-Za-z ]*M527" );

# All models with a fixed 2405130_000069 version
sixty_nine = make_list( "LaserJet[A-Za-z ]*M607",
                        "LaserJet[A-Za-z ]*M608",
                        "LaserJet[A-Za-z ]*M609",
                        "LaserJet[A-Za-z ]*E60055",
                        "LaserJet[A-Za-z ]*E60065",
                        "LaserJet[A-Za-z ]*E60075" );

# All models with a fixed 2405129_000059 version
fifty_nine = make_list( "LaserJet[A-Za-z ]*M806" );

# All models with a fixed 2405129_000058 version
fifty_eight = make_list( "LaserJet[A-Za-z ]*MFP M725" );

# All models with a fixed 2405129_000050 version
fifty = make_list( "OfficeJet[A-Za-z ]*Color Flow MFP X585",
                   "OfficeJet[A-Za-z ]*Color MFP X585" );

# All models with a fixed 2405087_018564 version
five_sixty_four = make_list( "PageWide[A-Za-z ]*Color 765",
                             "PageWide[A-Za-z ]*Color E75160" );

# All models with a fixed 2405129_000066 version
sixty_six = make_list( "PageWide[A-Za-z ]*Color MFP 586",
                       "PageWide[A-Za-z ]*Color Flow MFP 586" );

# All models with a fixed 2405087_018548 version
five_forty_eight = make_list( "PageWide[A-Za-z ]*Color MPF 780",
                              "PageWide[A-Za-z ]*Color MPF 785",
                              "PageWide[A-Za-z ]*Color Flow MFP E77650",
                              "PageWide[A-Za-z ]*Color Flow MFP E77660",
                              "PageWide[A-Za-z ]*Color MFP E77650" );

# All models with a fixed 2405129_000051 version
fifty_one = make_list( "PageWide[A-Za-z ]*Color X556",
                       "PageWide[A-Za-z ]*Color E55650" );

# All models with a fixed 2405087_018552 version
five_fifty_two = make_list( "ScanJet[A-Za-z ]*Flow N9120 Doc Flatbed Scanner" );

# All models with a fixed 2405087_018553 version
five_fifty_three = make_list( "Digital Sender Flow 8500 fn2 Doc Capture Workstation" );

function check_vuln_firmware( fixed_version ) {
  local_var fixed_version;

  if( fixed_version && version_is_less( version: version, test_version: fixed_version ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: fixed_version );
    security_message( data: report, port: 0 );
    exit( 0 );
  }
}

foreach pattern( forty_one) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000041" );
  }
}

foreach pattern( forty_seven ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000047" );
  }
}

foreach pattern( sixty_eight ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000068" );
  }
}

foreach pattern( thirty_eight ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000038" );
  }
}

foreach pattern( three_fifteen ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2308903_577315" );
  }
}

foreach pattern( forty_two ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000042" );
  }
}

foreach pattern( forty_five ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000045" );
  }
}

foreach pattern( forty_eight ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000048" );
  }
}

foreach pattern( sixty_one ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000061" );
  }
}

foreach pattern( fifty_seven ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000057" );
  }
}

foreach pattern( fifty_four ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000054" );
  }
}

foreach pattern( sixty ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000060" );
  }
}

foreach pattern( forty ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_00040" );
  }
}

foreach pattern( thirty_nine ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000039" );
  }
}

foreach pattern( sixty_nine ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405130_000069" );
  }
}

foreach pattern( fifty_nine ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000059" );
  }
}

foreach pattern( fifty_eight ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000058" );
  }
}

foreach pattern( fifty ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000050" );
  }
}

foreach pattern( five_sixty_four ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405087_18564" );
  }
}

foreach pattern( sixty_six ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000066" );
  }
}

foreach pattern( five_forty_eight ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405087_018548" );
  }
}

foreach pattern( fifty_one ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000051" );
  }
}

foreach pattern( five_fifty_two ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405087_018552" );
  }
}

foreach pattern( five_fifty_three ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405087_018223" );
  }
}

exit( 99 );
