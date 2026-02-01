# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20028.1");
  script_cve_id("CVE-2025-67724", "CVE-2025-67725", "CVE-2025-67726");
  script_tag(name:"creation_date", value:"2026-01-16 04:26:57 +0000 (Fri, 16 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-22 18:49:24 +0000 (Mon, 22 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20028-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20028-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620028-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254905");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023776.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-tornado6' package(s) announced via the SUSE-SU-2026:20028-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-tornado6 fixes the following issues:

- CVE-2025-67724: unescaped `reason` argument used in HTTP headers and in HTML default error pages can be used by
 attackers to launch header injection or XSS attacks (bsc#1254903).
- CVE-2025-67725: quadratic complexity of string concatenation operations used by the `HTTPHeaders.add` method can lead
 o DoS when processing a maliciously crafted HTTP request (bsc#1254905).
- CVE-2025-67726: quadratic complexity algorithm used in the `_parseparam` function of `httputil.py` can lead to DoS
 when processing maliciously crafted parameters in a `Content-Disposition` header (bsc#1254904).");

  script_tag(name:"affected", value:"'python-tornado6' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"python313-tornado6", rpm:"python313-tornado6~6.5~160000.3.1", rls:"SLES16.0.0"))) {
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
