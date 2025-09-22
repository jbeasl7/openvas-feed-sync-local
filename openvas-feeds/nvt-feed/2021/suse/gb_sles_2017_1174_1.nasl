# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1174.1");
  script_cve_id("CVE-2016-7175", "CVE-2016-7176", "CVE-2016-7177", "CVE-2016-7178", "CVE-2016-7179", "CVE-2016-7180", "CVE-2016-9373", "CVE-2016-9374", "CVE-2016-9375", "CVE-2016-9376", "CVE-2017-5596", "CVE-2017-5597", "CVE-2017-6014", "CVE-2017-7700", "CVE-2017-7701", "CVE-2017-7702", "CVE-2017-7703", "CVE-2017-7704", "CVE-2017-7705", "CVE-2017-7745", "CVE-2017-7746", "CVE-2017-7747", "CVE-2017-7748");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:59 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-18 21:02:41 +0000 (Tue, 18 Apr 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1174-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1174-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171174-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998964");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-May/002844.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2017:1174-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Wireshark was updated to version 2.0.12, which brings several new features, enhancements and bug fixes.

These security issues were fixed:

- CVE-2017-7700: In Wireshark the NetScaler file parser could go into an infinite loop, triggered by a malformed capture file. This was addressed in wiretap/netscaler.c by ensuring a nonzero record size (bsc#1033936).
- CVE-2017-7701: In Wireshark the BGP dissector could go into an infinite loop, triggered by packet injection or a malformed capture file. This was addressed in epan/dissectors/packet-bgp.c by using a different integer data type (bsc#1033937).
- CVE-2017-7702: In Wireshark the WBXML dissector could go into an infinite loop, triggered by packet injection or a malformed capture file. This was addressed in epan/dissectors/packet-wbxml.c by adding length validation (bsc#1033938).
- CVE-2017-7703: In Wireshark the IMAP dissector could crash, triggered by packet injection or a malformed capture file. This was addressed in epan/dissectors/packet-imap.c by calculating a line's end correctly (bsc#1033939).
- CVE-2017-7704: In Wireshark the DOF dissector could go into an infinite loop, triggered by packet injection or a malformed capture file. This was addressed in epan/dissectors/packet-dof.c by using a different integer data type and adjusting a return value (bsc#1033940).
- CVE-2017-7705: In Wireshark the RPC over RDMA dissector could go into an infinite loop, triggered by packet injection or a malformed capture file. This was addressed in epan/dissectors/packet-rpcrdma.c by correctly checking for going beyond the maximum offset (bsc#1033941).
- CVE-2017-7745: In Wireshark the SIGCOMP dissector could go into an infinite loop, triggered by packet injection or a malformed capture file. This was addressed in epan/dissectors/packet-sigcomp.c by correcting a memory-size check (bsc#1033942).
- CVE-2017-7746: In Wireshark the SLSK dissector could go into an infinite loop, triggered by packet injection or a malformed capture file. This was addressed in epan/dissectors/packet-slsk.c by adding checks for the remaining length (bsc#1033943).
- CVE-2017-7747: In Wireshark the PacketBB dissector could crash, triggered by packet injection or a malformed capture file. This was addressed in epan/dissectors/packet-packetbb.c by restricting additions to the protocol tree (bsc#1033944).
- CVE-2017-7748: In Wireshark the WSP dissector could go into an infinite loop, triggered by packet injection or a malformed capture file. This was addressed in epan/dissectors/packet-wsp.c by adding a length check (bsc#1033945).
- CVE-2016-7179: Stack-based buffer overflow in epan/dissectors/packet-catapult-dct2000.c in the Catapult DCT2000 dissector in Wireshark allowed remote attackers to cause a denial of service (application crash) via a crafted packet (bsc#998963).
- CVE-2016-9376: In Wireshark the OpenFlow dissector could crash with memory exhaustion, ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.0.12~36.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.0.12~36.1", rls:"SLES11.0SP4"))) {
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
