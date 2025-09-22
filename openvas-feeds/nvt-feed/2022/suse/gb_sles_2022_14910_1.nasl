# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.14910.1");
  script_cve_id("CVE-2014-10070", "CVE-2014-10071", "CVE-2014-10072", "CVE-2016-10714", "CVE-2017-18205", "CVE-2017-18206", "CVE-2018-0502", "CVE-2018-1071", "CVE-2018-1083", "CVE-2018-13259", "CVE-2018-7549", "CVE-2019-20044");
  script_tag(name:"creation_date", value:"2022-03-15 04:11:51 +0000 (Tue, 15 Mar 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-26 14:19:59 +0000 (Fri, 26 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:14910-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:14910-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-202214910-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163882");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-March/010436.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zsh' package(s) announced via the SUSE-SU-2022:14910-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zsh fixes the following issues:

- CVE-2019-20044: Fixed an insecure dropping of privileges when unsetting
 the PRIVILEGED option (bsc#1163882).
- CVE-2018-13259: Fixed an unexpected truncation of long shebang lines (bsc#1107294).
- CVE-2018-7549: Fixed a crash when an empty hash table (bsc#1082991).
- CVE-2018-1083: Fixed a stack-based buffer overflow when using tab completion
 on directories with long names (bsc#1087026).
- CVE-2018-1071: Fixed a stack-based buffer overflow when executing certain
 commands (bsc#1084656).
- CVE-2018-0502: Fixed a mishandling of shebang lines (bsc#1107296).
- CVE-2017-18206: Fixed a buffer overflow related to symlink processing (bsc#1083002).
- CVE-2017-18205: Fixed an application crash when using cd with no
 arguments (bsc#1082998).
- CVE-2016-10714: Fixed a potential application crash when handling maximum
 length paths (bsc#1083250).
- CVE-2014-10072: Fixed a buffer overflow when scanning very long directory
 paths for symbolic links (bsc#1082975).
- CVE-2014-10071: Fixed a buffer overflow when redirecting output to a long
 file descriptor (bsc#1082977).
- CVE-2014-10070: Fixed a privilege escalation vulnerability via environment
 variables (bsc#1082885).");

  script_tag(name:"affected", value:"'zsh' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"zsh", rpm:"zsh~4.3.6~67.9.8.1", rls:"SLES11.0SP4"))) {
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
