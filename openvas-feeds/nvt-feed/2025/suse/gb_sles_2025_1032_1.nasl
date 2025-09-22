# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1032.1");
  script_cve_id("CVE-2022-40982", "CVE-2022-41804", "CVE-2023-22655", "CVE-2023-23583", "CVE-2023-23908", "CVE-2023-28746", "CVE-2023-38575", "CVE-2023-39368", "CVE-2023-42667", "CVE-2023-43490", "CVE-2023-45733", "CVE-2023-45745", "CVE-2023-46103", "CVE-2023-47855", "CVE-2023-49141", "CVE-2024-21820", "CVE-2024-21853", "CVE-2024-23918", "CVE-2024-23984", "CVE-2024-24853", "CVE-2024-24968", "CVE-2024-24980", "CVE-2024-25939", "CVE-2024-31068", "CVE-2024-36293", "CVE-2024-37020", "CVE-2024-39355");
  script_tag(name:"creation_date", value:"2025-03-28 04:07:29 +0000 (Fri, 28 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-28 17:07:45 +0000 (Tue, 28 Nov 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1032-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1032-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251032-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237096");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/334663");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/336345");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/336562");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/337346");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/338025");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/338848");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/338854");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/341079");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/613537");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/615213");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/631123");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/634542");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/634897");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/636674");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/637780");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/682436");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/709192");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/714069");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/714071");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/740518");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/764616");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/772415");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/792254");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/793902");
  script_xref(name:"URL", value:"https://cdrdv2.intel.com/v1/dl/getContent/820922");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020609.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00828.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00836.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00837.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00898.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00950.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00960.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00972.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00982.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01036.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01038.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01045.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01046.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01051.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01052.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01079.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01083.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01097.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01100.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01101.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01103.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01118.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01139.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01166.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01194.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01213.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01228.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl' package(s) announced via the SUSE-SU-2025:1032-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for microcode_ctl fixes the following issues:

 - CVE-2024-31068: Improper Finite State Machines (FSMs) in Hardware
 Logic for some Intel Processors may allow privileged user to
 potentially enable denial of service via local access. (bsc#1237096)
 - CVE-2024-36293: A potential security vulnerability in some Intel
 Software Guard Extensions (Intel SGX) Platforms may allow denial
 of service. Intel is releasing microcode updates to mitigate this
 potential vulnerability. (bsc#1237096)
 - CVE-2024-39355: A potential security vulnerability in some
 13th and 14th Generation Intel Core Processors may allow denial
 of service. Intel is releasing microcode and UEFI reference code
 updates to mitigate this potential vulnerability. (bsc#1237096)
 - CVE-2024-37020: A potential security vulnerability in the Intel
 Data Streaming Accelerator (Intel DSA) for some Intel Xeon Processors
 may allow denial of service. Intel is releasing software updates to
 mitigate this potential vulnerability. (bsc#1237096)
 - CVE-2024-21853: Faulty finite state machines (FSMs) in the hardware logic
 in some 4th and 5th Generation Intel Xeon Processors may allow an
 authorized user to potentially enable denial of service via local access. (bsc#1233313)
 - CVE-2024-23918: Improper conditions check in some Intel Xeon processor
 memory controller configurations when using Intel SGX may allow a
 privileged user to potentially enable escalation of privilege via
 local access. (bsc#1233313)
 - CVE-2024-21820: Incorrect default permissions in some Intel Xeon processor
 memory controller configurations when using Intel SGX may allow a privileged
 user to potentially enable escalation of privilege via local access. (bsc#1233313)
 - CVE-2024-24968: Improper finite state machines (FSMs) in hardware logic in
 some Intel Processors may allow an privileged user to potentially enable a
 denial of service via local access. (bsc#1230400)
 - CVE-2024-23984: Observable discrepancy in RAPL interface for some Intel
 Processors may allow a privileged user to potentially enable information
 disclosure via local access. (bsc#1230400)
 - CVE-2024-24853: Incorrect behavior order in transition between executive
 monitor and SMI transfer monitor (STM) in some Intel(R) Processor may
 allow a privileged user to potentially enable escalation of privilege
 via local access. (bsc#1229129)
 - CVE-2024-25939: Mirrored regions with different values in 3rd Generation Intel(R)
 Xeon(R) Scalable Processors may allow a privileged user to potentially enable
 denial of service via local access. (bsc#1229129)
 - CVE-2024-24980: Protection mechanism failure in some 3rd, 4th, and 5th Generation
 Intel(R) Xeon(R) Processors may allow a privileged user to potentially enable
 escalation of privilege via local access. (bsc#1229129)
 - CVE-2023-42667: Improper isolation in the Intel(R) Core(TM) Ultra Processor stream
 cache mechanism may ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'microcode_ctl' package(s) on SUSE Linux Enterprise Server 11-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~1.17~102.83.81.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
