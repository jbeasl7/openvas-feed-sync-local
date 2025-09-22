# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123175");
  script_cve_id("CVE-2014-6040", "CVE-2014-8121");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:19 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-0327)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0327");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0327.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the ELSA-2015-0327 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.17-78.0.1]
- Remove strstr and strcasestr implementations using sse4.2 instructions.
- Upstream commits 584b18eb4df61ccd447db2dfe8c8a7901f8c8598 and
 1818483b15d22016b0eae41d37ee91cc87b37510 backported.

[2.17-78]
- Fix ppc64le builds (#1077389).

[2.17-77]
- Fix parsing of numeric hosts in gethostbyname_r (CVE-2015-0235, #1183545).

[2.17-76]
- Fix application crashes during calls to gettimeofday on ppc64
 when kernel exports gettimeofday via VDSO (#1077389).
- Prevent NSS-based file backend from entering infinite loop
 when different APIs request the same service (CVE-2014-8121, #1182272).

[2.17-75]
- Fix permission of debuginfo source files to allow multiarch
 debuginfo packages to be installed and upgraded (#1170110).

[2.17-74]
- Fix wordexp() to honour WRDE_NOCMD (CVE-2014-7817, #1170487).

[2.17-73]
- ftell: seek to end only when there are unflushed bytes (#1156331).

[2.17-72]
- [s390] Fix up _dl_argv after adjusting arguments in _dl_start_user (#1161666).

[2.17-71]
- Fix incorrect handling of relocations in 64-bit LE mode for Power
 (#1162847).

[2.17-70]
- [s390] Retain stack alignment when skipping over loader argv (#1161666).

[2.17-69]
- Use __int128_t in link.h to support older compiler (#1120490).

[2.17-68]
- Revert to defining __extern_inline only for gcc-4.3+ (#1120490).

[2.17-67]
- Correct a defect in the generated math error table in the manual (#786638).

[2.17-66]
- Include preliminary thread, signal and cancellation safety documentation
 in manual (#786638).

[2.17-65]
- PowerPC 32-bit and 64-bit optimized function support using STT_GNU_IFUNC
 (#731837).
- Support running Intel MPX-enabled applications (#1132518).
- Support running Intel AVX-512-enabled applications (#1140272).

[2.17-64]
- Fix crashes on invalid input in IBM gconv modules (#1140474, CVE-2014-6040).

[2.17-63]
- Build build-locale-archive statically (#1070611).
- Return failure in getnetgrent only when all netgroups have been searched
 (#1085313).

[2.17-62]
- Don't use alloca in addgetnetgrentX (#1138520).
- Adjust pointers to triplets in netgroup query data (#1138520).

[2.17-61]
- Set CS_PATH to just /use/bin (#1124453).
- Add systemtap probe in lll_futex_wake for ppc and s390 (#1084089).

[2.17-60]
- Add mmap usage to malloc_info output (#1103856).
- Fix nscd lookup for innetgr when netgroup has wildcards (#1080766).
- Fix memory order when reading libgcc handle (#1103874).
- Fix typo in nscd/selinux.c (#1125306).
- Do not fail if one of the two responses to AF_UNSPEC fails (#1098047).

[2.17-59]
- Provide correct buffer length to netgroup queries in nscd (#1083647).
- Return NULL for wildcard values in getnetgrent from nscd (#1085290).
- Avoid overlapping addresses to stpcpy calls in nscd (#1083644).
- Initialize all of datahead structure in nscd (#1083646).

[2.17-58]
- Remove gconv transliteration loadable modules support (CVE-2014-5119,
 - _nl_find_locale: Improve ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'glibc' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~78.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.17~78.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~78.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.17~78.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.17~78.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.17~78.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~78.0.1.el7", rls:"OracleLinux7"))) {
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
