# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104247");
  script_version("2025-05-16T05:40:21+0000");
  script_cve_id("CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21166");
  script_tag(name:"last_modification", value:"2025-05-16 05:40:21 +0000 (Fri, 16 May 2025)");
  script_tag(name:"creation_date", value:"2022-07-14 08:04:34 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-07 11:15:00 +0000 (Thu, 07 Jul 2022)");
  script_name("Missing Linux Kernel mitigations for 'Processor MMIO Stale Data' hardware vulnerabilities (INTEL-SA-00615)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_hw_vuln_linux_kernel_mitigation_detect.nasl",
                      "gb_gather_hardware_info_ssh_login.nasl");
  script_mandatory_keys("ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable");

  script_xref(name:"URL", value:"https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/processor_mmio_stale_data.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00615.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/processors-affected-consolidated-product-cpu-model.html");

  script_tag(name:"summary", value:"The remote host is missing one or more known mitigation(s) on
  Linux Kernel side for the referenced 'Processor MMIO Stale Data' hardware vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks previous gathered information on the mitigation status
  reported by the Linux Kernel.");

  script_tag(name:"affected", value:"Various Intel CPUs. Please see the references for the full list
  of affected CPUs.");

  script_tag(name:"solution", value:"The following solutions exist:

  - Update to a more recent Linux Kernel to receive mitigations on Kernel level and info about
  the mitigation status from it

  - Enable the mitigation(s) in the Linux Kernel (might be disabled depending on the configuration)

  Additional possible mitigations (if provided by the vendor) are to:

  - install a Microcode update

  - update the BIOS of the Mainboard

  Note: Please create an override for this result if one of the following applies:

  - the sysfs file is not available but other mitigations like a Microcode update is already in
  place

  - the sysfs file is not available but the CPU of the host is not affected

  - the reporting of the Linux Kernel is not correct (this is out of the control of this VT)");

  script_tag(name:"qod", value:"80"); # nb: None of the existing QoD types are matching here
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("list_array_func.inc");
include("host_details.inc");

if( ! get_kb_item( "ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable" ) )
  exit( 99 );

covered_vuln = "mmio_stale_data";

if( ! mitigation_status = get_kb_item( "ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable/" + covered_vuln ) )
  exit( 99 );

# nb: Only Intel CPUs affected. But we're only checking this if the sysfs file is missing and
# otherwise trust the Linux kernel (at least for now) that it reports the CPU as "Not affected"
# correctly.
if( "sysfs file missing (" >< mitigation_status ) {
  cpu_vendor_id = get_kb_item( "ssh/login/cpu_vendor_id" );
  if( cpu_vendor_id && "GenuineIntel" >!< cpu_vendor_id )
    exit( 99 );
}

report = 'The Linux Kernel on the remote host is missing the mitigation for the "' + covered_vuln + '" hardware vulnerabilities as reported by the sysfs interface:\n\n';

path = "/sys/devices/system/cpu/vulnerabilities/" + covered_vuln;
info[path] = mitigation_status;

# nb:
# - Store link between gb_hw_vuln_linux_kernel_mitigation_detect.nasl and this VT
# - We don't want to use get_app_* functions as we're only interested in the cross-reference here
register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.108765" ); # gb_hw_vuln_linux_kernel_mitigation_detect.nasl
register_host_detail( name:"detected_at", value:"general/tcp" ); # nb: gb_hw_vuln_linux_kernel_mitigation_detect.nasl is using port:0

report += text_format_table( array:info, sep:" | ", columnheader:make_list( "sysfs file checked", "Linux Kernel status (SSH response)" ) );
report += '\n\nNotes on the "Linux Kernel status (SSH response)" column:';
report += '\n- sysfs file missing: The sysfs interface is available but the sysfs file for this specific vulnerability is missing. This means the current Linux Kernel doesn\'t know this vulnerability yet. Based on this it is assumed that it doesn\'t provide any mitigation and that the target system is vulnerable.';
report += '\n- Strings including "Mitigation:", "Not affected" or "Vulnerable" are reported directly by the Linux Kernel.';
report += '\n- All other strings are responses to various SSH commands.';

security_message( port:0, data:report );
exit( 0 );
