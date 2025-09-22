# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2042.1");
  script_cve_id("CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1124", "CVE-2018-1125", "CVE-2018-1126");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:42 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-22 13:51:14 +0000 (Fri, 22 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2042-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2042-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182042-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092100");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-July/004299.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'procps' package(s) announced via the SUSE-SU-2018:2042-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for procps fixes the following security issues:

- CVE-2018-1122: Prevent local privilege escalation in top. If a user ran top
 with HOME unset in an attacker-controlled directory, the attacker could have
 achieved privilege escalation by exploiting one of several vulnerabilities in
 the config_file() function (bsc#1092100).
- CVE-2018-1123: Prevent denial of service in ps via mmap buffer overflow.
 Inbuilt protection in ps maped a guard page at the end of the overflowed
 buffer, ensuring that the impact of this flaw is limited to a crash (temporary
 denial of service) (bsc#1092100).
- CVE-2018-1124: Prevent multiple integer overflows leading to a heap
 corruption in file2strvec function. This allowed a privilege escalation for a
 local attacker who can create entries in procfs by starting processes, which
 could result in crashes or arbitrary code execution in proc utilities run by
 other users (bsc#1092100).
- CVE-2018-1125: Prevent stack buffer overflow in pgrep. This vulnerability was
 mitigated by FORTIFY limiting the impact to a crash (bsc#1092100).
- CVE-2018-1126: Ensure correct integer size in proc/alloc.* to prevent
 truncation/integer overflow issues (bsc#1092100).");

  script_tag(name:"affected", value:"'procps' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"procps", rpm:"procps~3.2.7~152.31.1", rls:"SLES11.0SP4"))) {
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
