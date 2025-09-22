# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1765");
  script_cve_id("CVE-2024-12086", "CVE-2024-12088");
  script_tag(name:"creation_date", value:"2025-08-06 04:43:07 +0000 (Wed, 06 Aug 2025)");
  script_version("2025-08-08T05:44:56+0000");
  script_tag(name:"last_modification", value:"2025-08-08 05:44:56 +0000 (Fri, 08 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-18 16:29:29 +0000 (Wed, 18 Jun 2025)");

  script_name("Huawei EulerOS: Security Advisory for rsync (EulerOS-SA-2025-1765)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.13\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1765");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1765");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'rsync' package(s) announced via the EulerOS-SA-2025-1765 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in rsync. When using the `--safe-links` option, rsync fails to properly verify if a symbolic link destination contains another symbolic link within it. This results in a path traversal vulnerability, which may lead to arbitrary file write outside the desired directory.(CVE-2024-12088)

A flaw was found in rsync. It could allow a server to enumerate the contents of an arbitrary file from the client's machine. This issue occurs when files are being copied from a client to a server. During this process, the rsync server will send checksums of local data to the client to compare with in order to determine what data needs to be sent to the server. By sending specially constructed checksum values for arbitrary files, an attacker may be able to reconstruct the data of those files byte-by-byte based on the responses from the client.(CVE-2024-12086)");

  script_tag(name:"affected", value:"'rsync' package(s) on Huawei EulerOS Virtualization release 2.13.0.");

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

if(release == "EULEROSVIRT-2.13.0") {

  if(!isnull(res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.2.5~2.h5.eulerosv2r13", rls:"EULEROSVIRT-2.13.0"))) {
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
