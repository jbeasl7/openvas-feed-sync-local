# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108767");
  script_version("2025-05-27T05:40:44+0000");
  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2017-5753",
                "CVE-2017-5715",
                "CVE-2017-5754",
                "CVE-2019-1125",
                "CVE-2018-3639",
                "CVE-2018-3615",
                "CVE-2018-3620",
                "CVE-2018-3646",
                "CVE-2018-12126",
                "CVE-2018-12130",
                "CVE-2018-12127",
                "CVE-2019-11091",
                "CVE-2019-11135",
                "CVE-2018-12207",
                "CVE-2020-0543",
                "CVE-2022-21123",
                "CVE-2022-21125",
                "CVE-2022-21166",
                "CVE-2022-27672",
                "CVE-2022-29900",
                "CVE-2022-29901",
                "CVE-2022-40982",
                "CVE-2023-20569",
                "CVE-2023-28746",
                "CVE-2024-28956"
               );
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"creation_date", value:"2020-06-02 05:50:19 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-16 03:15:00 +0000 (Wed, 16 Aug 2023)");
  script_name("Missing Linux Kernel mitigations for hardware vulnerabilities (sysfs interface not available)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hw_vuln_linux_kernel_mitigation_detect.nasl");
  script_mandatory_keys("ssh/hw_vulns/kernel_mitigations/sysfs_not_available");

  script_xref(name:"URL", value:"https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html");
  script_xref(name:"URL", value:"https://comsec.ethz.ch/research/microarch/retbleed/");
  script_xref(name:"URL", value:"https://downfall.page/");
  script_xref(name:"URL", value:"https://comsec.ethz.ch/research/microarch/inception/");
  script_xref(name:"URL", value:"https://meltdownattack.com/");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01153.html");
  script_xref(name:"URL", value:"https://www.vusec.net/projects/training-solo/");

  script_tag(name:"summary", value:"The remote host is missing all known mitigation(s) on Linux
  Kernel side for the referenced hardware vulnerabilities.

  Note: The sysfs interface to read the migitation status from the Linux Kernel is not available.
  Based on this it is assumed that no Linux Kernel mitigations are available and that the host is
  affected by all vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks previous gathered information on the mitigation status
  reported by the Linux Kernel.");

  script_tag(name:"solution", value:"Enable the mitigation(s) in the Linux Kernel or update to a
  more recent Linux Kernel.");

  # nb: Unreliable (sysfs interface might not be available for some reason) and none of the existing
  # QoD types are matching here
  script_tag(name:"qod", value:"30");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");

if( ! get_kb_item( "ssh/hw_vulns/kernel_mitigations/sysfs_not_available" ) )
  exit( 99 );

report = get_kb_item( "ssh/hw_vulns/kernel_mitigations/sysfs_not_available/report" );
if( report ) {

  # nb:
  # - Store link between gb_hw_vuln_linux_kernel_mitigation_detect.nasl and this VT
  # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
  register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.108765" ); # gb_hw_vuln_linux_kernel_mitigation_detect.nasl
  register_host_detail( name:"detected_at", value:"general/tcp" ); # nb: gb_hw_vuln_linux_kernel_mitigation_detect.nasl is using port:0

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
