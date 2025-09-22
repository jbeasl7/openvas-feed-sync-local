# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0110.1");
  script_cve_id("CVE-2015-7830", "CVE-2015-8711", "CVE-2015-8712", "CVE-2015-8713", "CVE-2015-8714", "CVE-2015-8715", "CVE-2015-8716", "CVE-2015-8717", "CVE-2015-8718", "CVE-2015-8719", "CVE-2015-8720", "CVE-2015-8721", "CVE-2015-8722", "CVE-2015-8723", "CVE-2015-8724", "CVE-2015-8725", "CVE-2015-8726", "CVE-2015-8727", "CVE-2015-8728", "CVE-2015-8729", "CVE-2015-8730", "CVE-2015-8731", "CVE-2015-8732", "CVE-2015-8733");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:09 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-04 14:09:25 +0000 (Mon, 04 Jan 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0110-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0110-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160110-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960382");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-January/001798.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2016:0110-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update contains Wireshark 1.12.9 and fixes the following issues:

* CVE-2015-7830: pcapng file parser could crash while copying an interface filter (bsc#950437)
* CVE-2015-8711: epan/dissectors/packet-nbap.c in the NBAP dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1 does not validate conversation data, which allows remote attackers to cause a denial of service (NULL pointer dereference and application crash) via a crafted packet.
* CVE-2015-8712: The dissect_hsdsch_channel_info function in epan/dissectors/packet-umts_fp.c in the UMTS FP dissector in Wireshark 1.12.x before 1.12.9 does not validate the number of PDUs, which allows remote attackers to cause a denial of service (application crash) via a crafted packet.
* CVE-2015-8713: epan/dissectors/packet-umts_fp.c in the UMTS FP dissector in Wireshark 1.12.x before 1.12.9 does not properly reserve memory for channel ID mappings, which allows remote attackers to cause a denial of service (out-of-bounds memory access and application crash) via a crafted packet.
* CVE-2015-8714: The dissect_dcom_OBJREF function in epan/dissectors/packet-dcom.c in the DCOM dissector in Wireshark 1.12.x before 1.12.9 does not initialize a certain IPv4 data structure, which allows remote attackers to cause a denial of service (application crash) via a crafted packet.
* CVE-2015-8715: epan/dissectors/packet-alljoyn.c in the AllJoyn dissector in Wireshark 1.12.x before 1.12.9 does not check for empty arguments, which allows remote attackers to cause a denial of service (infinite loop) via a crafted packet.
* CVE-2015-8716: The init_t38_info_conv function in epan/dissectors/packet-t38.c in the T.38 dissector in Wireshark 1.12.x before 1.12.9 does not ensure that a conversation exists, which allows remote attackers to cause a denial of service (application crash) via a crafted packet.
* CVE-2015-8717: The dissect_sdp function in epan/dissectors/packet-sdp.c in the SDP dissector in Wireshark 1.12.x before 1.12.9 does not prevent use of a negative media count, which allows remote attackers to cause a denial of service (application crash) via a crafted packet.
* CVE-2015-8718: Double free vulnerability in epan/dissectors/packet-nlm.c in the NLM dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1, when the 'Match MSG/RES packets for async NLM' option is enabled, allows remote attackers to cause a denial of service (application crash) via a crafted packet.
* CVE-2015-8719: The dissect_dns_answer function in epan/dissectors/packet-dns.c in the DNS dissector in Wireshark 1.12.x before 1.12.9 mishandles the EDNS0 Client Subnet option, which allows remote attackers to cause a denial of service (application crash) via a crafted packet.
* CVE-2015-8720: The dissect_ber_GeneralizedTime function in epan/dissectors/packet-ber.c in the BER dissector in Wireshark 1.12.x before 1.12.9 and 2.0.x before 2.0.1 improperly ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.12.9~0.12.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.12.9~0.12.1", rls:"SLES11.0SP4"))) {
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
