# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122060");
  script_cve_id("CVE-2011-2939", "CVE-2011-3597");
  script_tag(name:"creation_date", value:"2015-10-06 11:12:25 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-1424)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1424");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1424.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the ELSA-2011-1424 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[4:5.10.1-119.1]
- 731246 (CVE-2011-2939)CVE-2011-2939 heap overflow - decoding Unicode string
- 743010 - perl: code injection vulnerability in Digest->new()
- Resolves: rhbz#743090, rhbz#743092");

  script_tag(name:"affected", value:"'perl' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.10.1~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Archive-Extract", rpm:"perl-Archive-Extract~0.38~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Archive-Tar", rpm:"perl-Archive-Tar~1.58~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-CGI", rpm:"perl-CGI~3.51~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-CPAN", rpm:"perl-CPAN~1.9402~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-CPANPLUS", rpm:"perl-CPANPLUS~0.88~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Compress-Raw-Zlib", rpm:"perl-Compress-Raw-Zlib~2.023~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Compress-Zlib", rpm:"perl-Compress-Zlib~2.020~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Digest-SHA", rpm:"perl-Digest-SHA~5.47~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ExtUtils-CBuilder", rpm:"perl-ExtUtils-CBuilder~0.27~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ExtUtils-Embed", rpm:"perl-ExtUtils-Embed~1.28~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ExtUtils-MakeMaker", rpm:"perl-ExtUtils-MakeMaker~6.55~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ExtUtils-ParseXS", rpm:"perl-ExtUtils-ParseXS~2.2003.0~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-File-Fetch", rpm:"perl-File-Fetch~0.26~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-IO-Compress-Base", rpm:"perl-IO-Compress-Base~2.020~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-IO-Compress-Zlib", rpm:"perl-IO-Compress-Zlib~2.020~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-IO-Zlib", rpm:"perl-IO-Zlib~1.09~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-IPC-Cmd", rpm:"perl-IPC-Cmd~0.56~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Locale-Maketext-Simple", rpm:"perl-Locale-Maketext-Simple~0.18~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Log-Message", rpm:"perl-Log-Message~0.02~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Log-Message-Simple", rpm:"perl-Log-Message-Simple~0.04~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Build", rpm:"perl-Module-Build~0.3500~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-CoreList", rpm:"perl-Module-CoreList~2.18~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Load", rpm:"perl-Module-Load~0.16~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Load-Conditional", rpm:"perl-Module-Load-Conditional~0.30~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Loaded", rpm:"perl-Module-Loaded~0.02~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Pluggable", rpm:"perl-Module-Pluggable~3.90~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Object-Accessor", rpm:"perl-Object-Accessor~0.34~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Package-Constants", rpm:"perl-Package-Constants~0.02~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Params-Check", rpm:"perl-Params-Check~0.26~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Parse-CPAN-Meta", rpm:"perl-Parse-CPAN-Meta~1.40~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Pod-Escapes", rpm:"perl-Pod-Escapes~1.04~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Pod-Simple", rpm:"perl-Pod-Simple~3.13~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Term-UI", rpm:"perl-Term-UI~0.20~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Test-Harness", rpm:"perl-Test-Harness~3.17~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Test-Simple", rpm:"perl-Test-Simple~0.92~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Time-HiRes", rpm:"perl-Time-HiRes~1.9721~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Time-Piece", rpm:"perl-Time-Piece~1.15~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-core", rpm:"perl-core~5.10.1~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-devel", rpm:"perl-devel~5.10.1~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libs", rpm:"perl-libs~5.10.1~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-parent", rpm:"perl-parent~0.221~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-suidperl", rpm:"perl-suidperl~5.10.1~119.el6_1.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-version", rpm:"perl-version~0.77~119.el6_1.1", rls:"OracleLinux6"))) {
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
