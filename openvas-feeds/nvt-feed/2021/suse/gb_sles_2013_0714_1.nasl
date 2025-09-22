# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0714.1");
  script_cve_id("CVE-2013-2475", "CVE-2013-2476", "CVE-2013-2477", "CVE-2013-2478", "CVE-2013-2479", "CVE-2013-2480", "CVE-2013-2481", "CVE-2013-2482", "CVE-2013-2483", "CVE-2013-2484", "CVE-2013-2485", "CVE-2013-2486", "CVE-2013-2487", "CVE-2013-2488");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0714-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0714-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130714-1/");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.6.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2013:0714-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"wireshark has been updated to 1.8.6 which fixes bugs and security issues:

Vulnerabilities fixed:

 * The TCP dissector could crash. wnpa-sec-2013-10 CVE-2013-2475
 * The HART/IP dissectory could go into an infinite loop. wnpa-sec-2013-11 CVE-2013-2476
 * The CSN.1 dissector could crash. wnpa-sec-2013-12 CVE-2013-2477
 * The MS-MMS dissector could crash. wnpa-sec-2013-13 CVE-2013-2478
 * The MPLS Echo dissector could go into an infinite loop. wnpa-sec-2013-14 CVE-2013-2479
 * The RTPS and RTPS2 dissectors could crash.
wnpa-sec-2013-15 CVE-2013-2480
 * The Mount dissector could crash. wnpa-sec-2013-16 CVE-2013-2481
 * The AMPQ dissector could go into an infinite loop.
wnpa-sec-2013-17 CVE-2013-2482
 * The ACN dissector could attempt to divide by zero.
wnpa-sec-2013-18 CVE-2013-2483
 * The CIMD dissector could crash. wnpa-sec-2013-19 CVE-2013-2484
 * The FCSP dissector could go into an infinite loop.
wnpa-sec-2013-20 CVE-2013-2485
 * The RELOAD dissector could go into an infinite loop.
wnpa-sec-2013-21 CVE-2013-2486 CVE-2013-2487
 * The DTLS dissector could crash. wnpa-sec-2013-22 CVE-2013-2488

More information about further bug fixes and updated protocol support are listed here:
[link moved to references]
>

Security Issue references:

 * CVE-2013-2475
>
 * CVE-2013-2476
>
 * CVE-2013-2477
>
 * CVE-2013-2478
>
 * CVE-2013-2479
>
 * CVE-2013-2480
>
 * CVE-2013-2481
>
 * CVE-2013-2482
>
 * CVE-2013-2483
>
 * CVE-2013-2484
>
 * CVE-2013-2485
>
 * CVE-2013-2486
>
 * CVE-2013-2487
>
 * CVE-2013-2488
>");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 10-SP4, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.6.14~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.6.14~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.6~0.2.1", rls:"SLES11.0SP2"))) {
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
