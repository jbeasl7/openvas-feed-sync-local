# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0590.1");
  script_cve_id("CVE-2025-24970", "CVE-2025-25193");
  script_tag(name:"creation_date", value:"2025-02-21 04:07:36 +0000 (Fri, 21 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-26 13:14:32 +0000 (Wed, 26 Mar 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0590-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0590-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250590-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237038");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020377.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netty, netty-tcnative' package(s) announced via the SUSE-SU-2025:0590-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for netty, netty-tcnative fixes the following issues:

- CVE-2025-24970: incorrect validation of packets by SslHandler can lead to a native crash. (bsc#1237037)
- CVE-2025-25193: unsafe reading of environment files can lead to an application crash. (bsc#1237038)

Update to netty version 4.1.118 and netty-tcnative version 2.0.70 Final.

Other fixes:

- Fix recycling in CodecOutputList.
- StreamBufferingEncoder: do not send header frame with priority by default.
- Notify event loop termination future of unexpected exceptions.
- Fix AccessControlException in GlobalEventExecutor.
- AdaptivePoolingAllocator: round chunk sizes up and reduce chunk release frequency.
- Support BouncyCastle FIPS for reading PEM files.
- Dns: correctly encode DnsPtrRecord.
- Provide Brotli settings without com.aayushatharva.brotli4j dependency.
- Make DefaultResourceLeak more resilient against OOM.
- OpenSslSession: add support to defensively check for peer certs.
- SslHandler: ensure buffers are never leaked when wrap(...) produces SSLException.
- Correcly handle comments appended to nameserver declarations.
- PcapWriteHandler: apply fixes so that the handler can append to an existing PCAP file when writing the global header.
- PcapWriteHandler: allow output of PCAP files larger than 2GB.
- Fix bugs in BoundedInputStream.
- Fix HTTP header validation bug.
- AdaptivePoolingAllocator: fix possible race condition in method offerToQueue(...).
- AdaptivePoolingAllocator: make sure the sentinel object Magazine.MAGAZINE_FREED not be replaced.
- Only try to use Zstd and Brotli if the native libs can be loaded.
- Bump BlockHound version to 1.0.10.RELEASE.
- Add details to TooLongFrameException message.
- AdaptivePoolingAllocator: correctly reuse chunks.
- AdaptivePoolingAllocator: don't fail when we run on a host with 1 core.
- AdaptivePoolingAllocator: correctly re-use central queue chunks and avoid OOM issue.
- Fix several memory management (leaks and missing checks) issues.");

  script_tag(name:"affected", value:"'netty, netty-tcnative' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"netty-tcnative", rpm:"netty-tcnative~2.0.70~150200.3.25.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"netty-tcnative", rpm:"netty-tcnative~2.0.70~150200.3.25.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"netty-tcnative", rpm:"netty-tcnative~2.0.70~150200.3.25.1", rls:"SLES15.0SP5"))) {
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
