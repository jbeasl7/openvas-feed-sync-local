# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107844");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2020-06-25 22:42:17 +0200 (Thu, 25 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-29 13:10:00 +0000 (Thu, 29 Mar 2018)");
  script_cve_id("CVE-2017-17250");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Out-Of-Bounds Write Vulnerability on Several Huawei Products (huawei-sa-20180214-01-ospf)");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is an out-of-bounds write vulnerability on several Huawei products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When a user executes a query command after the device received an abnormal OSPF message,
  the software writes data past the end of the intended buffer due to the insufficient verification of the input data. An
  unauthenticated, remote attacker could exploit this vulnerability by sending abnormal OSPF messages to the device. A
  successful exploit could cause the system to crash. (Vulnerability ID: HWPSIRT-2017-10017)");

  script_tag(name:"impact", value:"A successful exploit could cause the system to crash.");

  script_tag(name:"affected", value:"AR120-S versions V200R005C32

  AR1200 versions V200R005C32

  AR1200-S versions V200R005C32

  AR150 versions V200R005C32

  AR150-S versions V200R005C32

  AR160 versions V200R005C32

  AR200 versions V200R005C32

  AR200-S versions V200R005C32

  AR2200-S versions V200R005C32

  AR3200 versions V200R005C32 V200R007C00

  AR510 versions V200R005C32

  CloudEngine 12800 versions V100R003C00HP0002 V100R003C00HP0003 V100R003C00SPC501 V100R003C10 V100R003C10B052 V100R003C10B058 V100R003C10SPC100 V100R005C00 V100R005C10 V100R006C00

  NetEngine16EX versions V200R005C32

  S12700 versions V200R007C00 V200R007C01 V200R008C00

  S2700 versions V200R006C10 V200R007C00 V200R008C00

  S5700 versions V200R007C00 V200R008C00

  S6700 versions V200R008C00

  S7700 versions V200R007C00 V200R008C00

  S9700 versions V200R007C00 V200R007C01 V200R008C00

  SRG1300 versions V200R005C32

  SRG2300 versions V200R005C32

  SRG3300 versions V200R005C32");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180214-01-ospf-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:huawei:ar120-s_firmware",
                      "cpe:/o:huawei:ar1200_firmware",
                      "cpe:/o:huawei:ar1200-s_firmware",
                      "cpe:/o:huawei:ar150_firmware",
                      "cpe:/o:huawei:ar150-s_firmware",
                      "cpe:/o:huawei:ar160_firmware",
                      "cpe:/o:huawei:ar200_firmware",
                      "cpe:/o:huawei:ar200-s_firmware",
                      "cpe:/o:huawei:ar2200-s_firmware",
                      "cpe:/o:huawei:ar3200_firmware",
                      "cpe:/o:huawei:ar510_firmware",
                      "cpe:/o:huawei:cloudengine_12800_firmware",
                      "cpe:/o:huawei:netengine16ex_firmware",
                      "cpe:/o:huawei:s12700_firmware",
                      "cpe:/o:huawei:s2700_firmware",
                      "cpe:/o:huawei:s5700_firmware",
                      "cpe:/o:huawei:s6700_firmware",
                      "cpe:/o:huawei:s7700_firmware",
                      "cpe:/o:huawei:s9700_firmware",
                      "cpe:/o:huawei:srg1300_firmware",
                      "cpe:/o:huawei:srg2300_firmware",
                      "cpe:/o:huawei:srg3300_firmware" );

if( ! infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
version = toupper( infos["version"] );

patch = get_kb_item( "huawei/vrp/patch" );

if( cpe == "cpe:/o:huawei:ar120-s_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less(version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar1200_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less(version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar1200-s_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar150_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar150-s_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar160_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar200_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less(version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar200-s_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less(version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar2200-s_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar3200_firmware" ) {
  if( version =~ "^V200R005C32" || version =~ "^V200R007C00" ) {
    if( ! patch || version_is_less(version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:ar510_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:cloudengine_12800_firmware" ) {
  if( version =~ "^V100R003C00HP0002" || version =~ "^V100R003C00HP0003" || version =~ "^V100R003C00SPC501" ||
      version =~ "^V100R003C10" || version =~ "^V100R003C10B052" || version =~ "^V100R003C10B058" ||
      version =~ "^V100R003C10SPC100" || version =~ "^V100R005C00" || version =~ "^V100R005C10" ||
      version =~ "^V100R006C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R001C00SPC700" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R001C00SPC700" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:netengine16ex_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:s12700_firmware" ) {
  if( version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R008C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V2R9C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V2R9C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:s2700_firmware" ) {
  if( version =~ "^V200R006C10" || version =~ "^V200R007C00" || version =~ "^V200R008C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V2R9C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V2R9C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:s5700_firmware" ) {
  if( version =~ "^V200R007C00" || version =~ "^V200R008C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V2R9C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V2R9C00" );
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

else if( cpe == "cpe:/o:huawei:s6700_firmware" ) {
  if( version =~ "^V200R008C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V2R9C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V2R9C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:s7700_firmware" ) {
  if( version =~ "^V200R007C00" || version =~ "^V200R008C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V2R9C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V2R9C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:s9700_firmware" ) {
  if( version =~ "^V200R007C00" || version =~ "^V200R007C01" || version =~ "^V200R008C00" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V2R9C00" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V2R9C00" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:srg1300_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R007C00SPC900") ) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

else if( cpe == "cpe:/o:huawei:srg2300_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

else if( cpe == "cpe:/o:huawei:srg3300_firmware" ) {
  if( version =~ "^V200R005C32" ) {
    if( ! patch || version_is_less( version: patch, test_version: "V200R007C00SPC900" ) ) {
      report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V200R007C00SPC900" );
      security_message( port: 0, data: report );
      exit( 0 );
    }
  }
}

exit( 99 );
