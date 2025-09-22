# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0811.1");
  script_cve_id("CVE-2017-17997", "CVE-2018-7320", "CVE-2018-7321", "CVE-2018-7322", "CVE-2018-7323", "CVE-2018-7324", "CVE-2018-7325", "CVE-2018-7326", "CVE-2018-7327", "CVE-2018-7328", "CVE-2018-7329", "CVE-2018-7330", "CVE-2018-7331", "CVE-2018-7332", "CVE-2018-7333", "CVE-2018-7334", "CVE-2018-7335", "CVE-2018-7336", "CVE-2018-7337", "CVE-2018-7417", "CVE-2018-7418", "CVE-2018-7419", "CVE-2018-7420", "CVE-2018-7421");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-09 16:21:12 +0000 (Fri, 09 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0811-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0811-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180811-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082692");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-March/003842.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2018:0811-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wireshark fixes the following issues:

Security issue fixed (bsc#1082692):

- CVE-2018-7335: The IEEE 802.11 dissector could crash (wnpa-sec-2018-05)
- CVE-2018-7321: thrift long dissector loop (dissect_thrift_map)
- CVE-2018-7322: DICOM: inifinite loop (dissect_dcm_tag)
- CVE-2018-7323: WCCP: very long loop (dissect_wccp2_alternate_mask_value_set_element)
- CVE-2018-7324: SCCP: infinite loop (dissect_sccp_optional_parameters)
- CVE-2018-7325: RPKI-Router Protocol: infinite loop (dissect_rpkirtr_pdu)
- CVE-2018-7326: LLTD: infinite loop (dissect_lltd_tlv)
- CVE-2018-7327: openflow_v6: infinite loop (dissect_openflow_bundle_control_v6)
- CVE-2018-7328: USB-DARWIN: long loop (dissect_darwin_usb_iso_transfer)
- CVE-2018-7329: S7COMM: infinite loop (s7comm_decode_ud_cpu_alarm_main)
- CVE-2018-7330: thread_meshcop: infinite loop (get_chancount)
- CVE-2018-7331: GTP: infinite loop (dissect_gprscdr_GGSNPDPRecord, dissect_ber_set)
- CVE-2018-7332: RELOAD: infinite loop (dissect_statans)
- CVE-2018-7333: RPCoRDMA: infinite loop in get_write_list_chunk_count
- CVE-2018-7421: Multiple dissectors could go into large infinite loops (wnpa-sec-2018-06)
- CVE-2018-7334: The UMTS MAC dissector could crash (wnpa-sec-2018-07)
- CVE-2018-7337: The DOCSIS dissector could crash (wnpa-sec-2018-08)
- CVE-2018-7336: The FCP dissector could crash (wnpa-sec-2018-09)
- CVE-2018-7320: The SIGCOMP dissector could crash (wnpa-sec-2018-10)
- CVE-2018-7420: The pcapng file parser could crash (wnpa-sec-2018-11)
- CVE-2018-7417: The IPMI dissector could crash (wnpa-sec-2018-12)
- CVE-2018-7418: The SIGCOMP dissector could crash (wnpa-sec-2018-13)
- CVE-2018-7419: The NBAP disssector could crash (wnpa-sec-2018-14)
- CVE-2017-17997: Misuse of NULL pointer in MRDISC dissector (bsc#1077080).");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark8", rpm:"libwireshark8~2.2.13~48.21.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap6", rpm:"libwiretap6~2.2.13~48.21.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.2.13~48.21.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil7", rpm:"libwsutil7~2.2.13~48.21.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.2.13~48.21.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.2.13~48.21.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark8", rpm:"libwireshark8~2.2.13~48.21.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap6", rpm:"libwiretap6~2.2.13~48.21.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwscodecs1", rpm:"libwscodecs1~2.2.13~48.21.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil7", rpm:"libwsutil7~2.2.13~48.21.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.2.13~48.21.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gtk", rpm:"wireshark-gtk~2.2.13~48.21.1", rls:"SLES12.0SP3"))) {
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
