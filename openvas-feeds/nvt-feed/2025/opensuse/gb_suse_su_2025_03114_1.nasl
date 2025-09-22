# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03114.1");
  script_cve_id("CVE-2025-55163", "CVE-2025-58056", "CVE-2025-58057");
  script_tag(name:"creation_date", value:"2025-09-11 04:06:43 +0000 (Thu, 11 Sep 2025)");
  script_version("2025-09-11T05:38:37+0000");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-08 16:45:55 +0000 (Mon, 08 Sep 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03114-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03114-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503114-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249134");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041552.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netty, netty-tcnative' package(s) announced via the SUSE-SU-2025:03114-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for netty, netty-tcnative fixes the following issues:

Upgrade to upstream version 4.1.126.

Security issues fixed:

- CVE-2025-58057: decompression codecs allocating a large number of buffers after processing specially crafted input can
 cause a denial of service (bsc#1249134).
- CVE-2025-58056: incorrect parsing of chunk extensions can lead to request smuggling (bsc#1249116).
- CVE-2025-55163: 'MadeYouReset' denial of serivce attack in the HTTP/2 protocol (bsc#1247991).

Other issues fixed:

- Fixes from version 4.1.126
 * Fix IllegalReferenceCountException on invalid upgrade response.
 * Drop unknown frame on missing stream.
 * Don't try to handle incomplete upgrade request.
 * Update to netty-tcnative 2.0.73Final.

- Fixes from version 4.1.124
 * Fix NPE and AssertionErrors when many tasks are scheduled and cancelled.
 * HTTP2: Http2ConnectionHandler should always use Http2ConnectionEncoder.
 * Epoll: Correctly handle UDP packets with source port of 0.
 * Fix netty-common OSGi Import-Package header.
 * MqttConnectPayload.toString() includes password.

- Fixes from version 4.1.123
 * Fix chunk reuse bug in adaptive allocator.
 * More accurate adaptive memory usage accounting.
 * Introduce size-classes for the adaptive allocator.
 * Reduce magazine proliferation eagerness.
 * Fix concurrent ByteBuffer access issue in AdaptiveByteBuf.getBytes.
 * Fix possible buffer corruption caused by incorrect setCharSequence(...) implementation.
 * AdaptiveByteBuf: Fix AdaptiveByteBuf.maxFastWritableBytes() to take writerIndex() into account.
 * Optimize capacity bumping for adaptive ByteBufs.
 * AbstractDnsRecord: equals() and hashCode() to ignore name field's case.
 * Backport Unsafe guards.
 * Guard recomputed offset access with hasUnsafe.
 * HTTP2: Always produce a RST frame on stream exception.
 * Correct what artifacts included in netty-bom.

- Fixes from version 4.1.122
 * DirContextUtils.addNameServer(...) should just catch Exception internally.
 * Make public API specify explicit maxAllocation to prevent OOM.
 * Fix concurrent ByteBuf write access bug in adaptive allocator.
 * Fix transport-native-kqueue Bundle-SymbolicNames.
 * Fix resolver-dns-native-macos Bundle-SymbolicNames.
 * Always correctly calculate the memory address of the ByteBuf even if sun.misc.Unsafe is not usable.
 * Upgrade lz4 dependencies as the old version did not correctly handle ByteBuffer that have an arrayOffset > 0.
 * Optimize ByteBuf.setCharSequence for adaptive allocator.
 * Kqueue: Fix registration failure when fd is reused.
 * Make JdkZlibEncoder accept Deflater.DEFAULT_COMPRESSION as level.
 * Ensure OpenSsl.availableJavaCipherSuites does not contain null values.
 * Always prefer direct buffers for pooled allocators if not explicit disabled.
 * Update to netty-tcnative 2.0.72.Final.
 * Re-enable sun.misc.Unsafe by default on Java 24+.
 * Kqueue: Delay removal from registration map ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'netty, netty-tcnative' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"netty", rpm:"netty~4.1.126~150200.4.34.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-javadoc", rpm:"netty-javadoc~4.1.126~150200.4.34.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-tcnative", rpm:"netty-tcnative~2.0.73~150200.3.30.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-tcnative-javadoc", rpm:"netty-tcnative-javadoc~2.0.73~150200.3.30.1", rls:"openSUSELeap15.6"))) {
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
