# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1265.1");
  script_cve_id("CVE-2013-2486", "CVE-2013-2487", "CVE-2013-3555", "CVE-2013-3556", "CVE-2013-3557", "CVE-2013-3558", "CVE-2013-3559", "CVE-2013-3560", "CVE-2013-3561", "CVE-2013-3562", "CVE-2013-4074", "CVE-2013-4075", "CVE-2013-4076", "CVE-2013-4077", "CVE-2013-4078", "CVE-2013-4079", "CVE-2013-4080", "CVE-2013-4081", "CVE-2013-4082", "CVE-2013-4083");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1265-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1265-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131265-1/");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.8.8.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.8.7.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2013:1265-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This wireshark version update to 1.8.8 includes several security and general bug fixes.

Version update to 1.8.8 [bnc#824900]:

 * vulnerabilities fixed: o The CAPWAP dissector could crash. wnpa-sec-2013-32 CVE-2013-4074 o The GMR-1 BCCH dissector could crash. wnpa-sec-2013-33 CVE-2013-4075 o The PPP dissector could crash. wnpa-sec-2013-34 CVE-2013-4076 o The NBAP dissector could crash. wnpa-sec-2013-35 CVE-2013-4077 o The RDP dissector could crash.
wnpa-sec-2013-36 CVE-2013-4078 o The GSM CBCH dissector could crash. wnpa-sec-2013-37 CVE-2013-4079 o The Assa Abloy R3 dissector could consume excessive memory and CPU.
wnpa-sec-2013-38 CVE-2013-4080 o The HTTP dissector could overrun the stack. wnpa-sec-2013-39 CVE-2013-4081 o The Ixia IxVeriWave file parser could overflow the heap.
wnpa-sec-2013-40 CVE-2013-4082 o The DCP ETSI dissector could crash. wnpa-sec-2013-41 CVE-2013-4083
 * Further bug fixes and updated protocol support as listed in:
[link moved to references] l>

Version update to 1.8.7 [bnc#813217, bnc#820973]:

 * vulnerabilities fixed: o The RELOAD dissector could go into an infinite loop. wnpa-sec-2013-23 CVE-2013-2486 CVE-2013-2487 o The GTPv2 dissector could crash.
wnpa-sec-2013-24 o The ASN.1 BER dissector could crash.
wnpa-sec-2013-25 o The PPP CCP dissector could crash.
wnpa-sec-2013-26 o The DCP ETSI dissector could crash.
wnpa-sec-2013-27 o The MPEG DSM-CC dissector could crash.
wnpa-sec-2013-28 o The Websocket dissector could crash.
wnpa-sec-2013-29 o The MySQL dissector could go into an infinite loop. wnpa-sec-2013-30 o The ETCH dissector could go into a large loop. wnpa-sec-2013-31
 * Further bug fixes and updated protocol support as listed in:
[link moved to references] l>

Ohter bug fixes:

 * bnc#816517: 'Save As' Nokia libpcap corrupting the file
 * bnc#816887: wireshark crashed in 'SCTP' -> 'Prepare Filter for this Association'

Security Issue references:

 * CVE-2013-2486
>
 * CVE-2013-2487
>
 * CVE-2013-3555
>
 * CVE-2013-3556
>
 * CVE-2013-3557
>
 * CVE-2013-3558
>
 * CVE-2013-3559
>
 * CVE-2013-3560
>
 * CVE-2013-3561
>
 * CVE-2013-3562
>
 * CVE-2013-3561
>
 * CVE-2013-3561
>
 * CVE-2013-4074
>
 * CVE-2013-4075
>
 * CVE-2013-4076
>
 * CVE-2013-4077
>
 * CVE-2013-4078
>
 * CVE-2013-4079
>
 * CVE-2013-4080
>
 * CVE-2013-4081
>
 * CVE-2013-4082
>
 * CVE-2013-4083
>");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.8~0.2.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.8~0.2.1", rls:"SLES11.0SP3"))) {
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
