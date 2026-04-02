# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1532");
  script_cve_id("CVE-2025-14017", "CVE-2025-14524", "CVE-2025-15079", "CVE-2025-15224");
  script_tag(name:"creation_date", value:"2026-03-16 13:39:49 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-17T05:57:28+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:28 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2026-1532)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1532");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1532");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'curl' package(s) announced via the EulerOS-SA-2026-1532 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When an OAuth2 bearer token is used for an HTTP(S) transfer, and that transfer performs a cross-protocol redirect to a second URL that uses an IMAP, LDAP,POP3 or SMTP scheme, curl might wrongly pass on the bearer token to the new target host.(CVE-2025-14524)

When doing SSH-based transfers using either SCP or SFTP, and setting the known_hosts file, libcurl could still mistakenly accept connecting to hosts *not present* in the specified file if they were added as recognized in the libssh *global* known_hosts file.(CVE-2025-15079)

When doing SSH-based transfers using either SCP or SFTP, and asked to do public key authentication, curl would wrongly still ask and authenticate using a locally running SSH agent.(CVE-2025-15224)

When doing multi-threaded LDAPS transfers (LDAP over TLS) with libcurl,changing TLS options in one thread would inadvertently change them globallyand therefore possibly also affect other concurrently setup transfers.Disabling certificate verification for a specific transfer could unintentionally disable the feature for other threads as well.(CVE-2025-14017)");

  script_tag(name:"affected", value:"'curl' package(s) on Huawei EulerOS Virtualization release 2.10.1.");

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

if(release == "EULEROSVIRT-2.10.1") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.71.1~4.h31.r7.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.71.1~4.h31.r7.eulerosv2r10", rls:"EULEROSVIRT-2.10.1"))) {
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
