# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20607.1");
  script_cve_id("CVE-2025-11187", "CVE-2025-15467", "CVE-2025-15468", "CVE-2025-9230");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20607-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20607-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620607-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256880");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024609.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-3-livepatches' package(s) announced via the SUSE-SU-2026:20607-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-3-livepatches fixes the following issues:

- CVE-2025-11187: Fixed improper validation of PBMAC1 parameters in PKCS#12 MAC verification (bsc#1256878).
- CVE-2025-15467: Fixed stack buffer overflow in CMS AuthEnvelopedData parsing (bsc#1256876).
- CVE-2025-15468: Fixed NULL dereference in SSL_CIPHER_find() function on unknown cipher ID (bsc#1256880).
- CVE-2025-9230: Fixed out-of-bounds read & write in RFC 3211 KEK Unwrap (bsc#1250410).");

  script_tag(name:"affected", value:"'openssl-3-livepatches' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-livepatches", rpm:"openssl-3-livepatches~0.3~160000.1.1", rls:"SLES16.0.0"))) {
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
