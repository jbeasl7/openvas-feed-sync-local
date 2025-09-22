# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1377");
  script_cve_id("CVE-2024-12085", "CVE-2024-12086", "CVE-2024-12087", "CVE-2024-12088", "CVE-2024-12747");
  script_tag(name:"creation_date", value:"2025-04-11 04:27:44 +0000 (Fri, 11 Apr 2025)");
  script_version("2025-06-19T05:40:14+0000");
  script_tag(name:"last_modification", value:"2025-06-19 05:40:14 +0000 (Thu, 19 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-18 16:29:29 +0000 (Wed, 18 Jun 2025)");

  script_name("Huawei EulerOS: Security Advisory for rsync (EulerOS-SA-2025-1377)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1377");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1377");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'rsync' package(s) announced via the EulerOS-SA-2025-1377 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in rsync. When using the `--safe-links` option, the rsync client fails to properly verify if a symbolic link destination sent from the server contains another symbolic link within it. This results in a path traversal vulnerability, which may lead to arbitrary file write outside the desired directory.(CVE-2024-12088)

A path traversal vulnerability exists in rsync. It stems from behavior enabled by the `--inc-recursive` option, a default-enabled option for many client options and can be enabled by the server even if not explicitly enabled by the client. When using the `--inc-recursive` option, a lack of proper symlink verification coupled with deduplication checks occurring on a per-file-list basis could allow a server to write files outside of the client's intended destination directory. A malicious server could write malicious files to arbitrary locations named after valid directories/paths on the client.(CVE-2024-12087)

A flaw was found in rsync. It could allow a server to enumerate the contents of an arbitrary file from the client's machine. This issue occurs when files are being copied from a client to a server. During this process, the rsync server will send checksums of local data to the client to compare with in order to determine what data needs to be sent to the server. By sending specially constructed checksum values for arbitrary files, an attacker may be able to reconstruct the data of those files byte-by-byte based on the responses from the client.(CVE-2024-12086)

A flaw was found in rsync which could be triggered when rsync compares file checksums. This flaw allows an attacker to manipulate the checksum length (s2length) to cause a comparison between a checksum and uninitialized memory and leak one byte of uninitialized stack data at a time.(CVE-2024-12085)

A flaw was found in rsync. This vulnerability arises from a race condition during rsync's handling of symbolic links. Rsync's default behavior when encountering symbolic links is to skip them. If an attacker replaced a regular file with a symbolic link at the right time, it was possible to bypass the default behavior and traverse symbolic links. Depending on the privileges of the rsync process, an attacker could leak sensitive information, potentially leading to privilege escalation.(CVE-2024-12747)");

  script_tag(name:"affected", value:"'rsync' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.2.3~2.h9.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
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
