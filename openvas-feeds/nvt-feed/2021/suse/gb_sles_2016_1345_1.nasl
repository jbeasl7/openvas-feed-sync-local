# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1345.1");
  script_cve_id("CVE-2016-2523", "CVE-2016-2530", "CVE-2016-2531", "CVE-2016-2532");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-02 15:27:18 +0000 (Wed, 02 Mar 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1345-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1345-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161345-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976944");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-May/002069.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.10.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.11.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2016:1345-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update to Wireshark 1 12.11 fixes a number of issues in protocol dissectors that could have allowed a remote attacker to crash Wireshark or cause excessive CPU usage through specially crafted packages inserted into the network or a capture file.

- The PKTC dissector could crash (wnpa-sec-2016-22)
- The PKTC dissector could crash (wnpa-sec-2016-23)
- The IAX2 dissector could go into an infinite loop (wnpa-sec-2016-24)
- Wireshark and TShark could exhaust the stack (wnpa-sec-2016-25)
- The GSM CBCH dissector could crash (wnpa-sec-2016-26)
- The NCP dissector could crash (wnpa-sec-2016-28)
- CVE-2016-2523: DNP dissector infinite loop (wnpa-sec-2016-03)
- CVE-2016-2530: RSL dissector crash (wnpa-sec-2016-10)
- CVE-2016-2531: RSL dissector crash (wnpa-sec-2016-10)
- CVE-2016-2532: LLRP dissector crash (wnpa-sec-2016-11)
- GSM A-bis OML dissector crash (wnpa-sec-2016-14)
- ASN.1 BER dissector crash (wnpa-sec-2016-15)
- ASN.1 BER dissector crash (wnpa-sec-2016-18)

Also containsfurther bug fixes and updated protocol support as listed in:
[links moved to references]");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.12.11~0.18.1", rls:"SLES11.0SP4"))) {
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
