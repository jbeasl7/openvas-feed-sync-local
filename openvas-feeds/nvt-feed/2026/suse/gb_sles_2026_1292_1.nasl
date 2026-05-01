# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1292.1");
  script_cve_id("CVE-2025-13462", "CVE-2026-3479", "CVE-2026-3644", "CVE-2026-4224", "CVE-2026-4519");
  script_tag(name:"creation_date", value:"2026-04-15 04:59:08 +0000 (Wed, 15 Apr 2026)");
  script_version("2026-04-15T06:17:01+0000");
  script_tag(name:"last_modification", value:"2026-04-15 06:17:01 +0000 (Wed, 15 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1292-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1292-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261292-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1260026");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-April/025310.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python312' package(s) announced via the SUSE-SU-2026:1292-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python312 fixes the following issues:

- CVE-2025-13462: incorrect parsing of TarInfo when GNU long name and type AREGTYPE are combined can lead to
 misinterpretation of tar archives (bsc#1259611).
- CVE-2026-3479: improper resource argument validation in `pkgutil.get_data()` can lead to path traversal (bsc#1259989).
- CVE-2026-3644: incomplete control character validation in http.cookies can lead to input validation bypass
 (bsc#1259734).
- CVE-2026-4224: parsing XML with deeply nested DTD content models can lead to C stack overflow (bsc#1259735).
- CVE-2026-4519: failure to sanitize leading dashes in URLs in the `webbrowser.open()` API can lead to web browser
 command line option injection (bsc#1260026).");

  script_tag(name:"affected", value:"'python312' package(s) on SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_12-1_0", rpm:"libpython3_12-1_0~3.12.13~150600.3.53.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312", rpm:"python312~3.12.13~150600.3.53.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-base", rpm:"python312-base~3.12.13~150600.3.53.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-curses", rpm:"python312-curses~3.12.13~150600.3.53.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-dbm", rpm:"python312-dbm~3.12.13~150600.3.53.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-devel", rpm:"python312-devel~3.12.13~150600.3.53.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-idle", rpm:"python312-idle~3.12.13~150600.3.53.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-tk", rpm:"python312-tk~3.12.13~150600.3.53.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-tools", rpm:"python312-tools~3.12.13~150600.3.53.1", rls:"SLES15.0SP6"))) {
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
