# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4619.1");
  script_cve_id("CVE-2009-0316", "CVE-2016-1248", "CVE-2017-17087", "CVE-2017-5953", "CVE-2017-6349", "CVE-2017-6350", "CVE-2021-3778", "CVE-2021-3796", "CVE-2021-3872", "CVE-2021-3875", "CVE-2021-3903", "CVE-2021-3927", "CVE-2021-3928", "CVE-2021-3968", "CVE-2021-3973", "CVE-2021-3974", "CVE-2021-3984", "CVE-2021-4019", "CVE-2021-4069", "CVE-2021-4136", "CVE-2021-4166", "CVE-2021-4192", "CVE-2021-4193", "CVE-2021-46059", "CVE-2022-0128", "CVE-2022-0213", "CVE-2022-0261", "CVE-2022-0318", "CVE-2022-0319", "CVE-2022-0351", "CVE-2022-0359", "CVE-2022-0361", "CVE-2022-0392", "CVE-2022-0407", "CVE-2022-0413", "CVE-2022-0696", "CVE-2022-1381", "CVE-2022-1420", "CVE-2022-1616", "CVE-2022-1619", "CVE-2022-1620", "CVE-2022-1720", "CVE-2022-1733", "CVE-2022-1735", "CVE-2022-1771", "CVE-2022-1785", "CVE-2022-1796", "CVE-2022-1851", "CVE-2022-1897", "CVE-2022-1898", "CVE-2022-1927", "CVE-2022-1968", "CVE-2022-2124", "CVE-2022-2125", "CVE-2022-2126", "CVE-2022-2129", "CVE-2022-2175", "CVE-2022-2182", "CVE-2022-2183", "CVE-2022-2206", "CVE-2022-2207", "CVE-2022-2208", "CVE-2022-2210", "CVE-2022-2231", "CVE-2022-2257", "CVE-2022-2264", "CVE-2022-2284", "CVE-2022-2285", "CVE-2022-2286", "CVE-2022-2287", "CVE-2022-2304", "CVE-2022-2343", "CVE-2022-2344", "CVE-2022-2345", "CVE-2022-2522", "CVE-2022-2571", "CVE-2022-2580", "CVE-2022-2581", "CVE-2022-2598", "CVE-2022-2816", "CVE-2022-2817", "CVE-2022-2819", "CVE-2022-2845", "CVE-2022-2849", "CVE-2022-2862", "CVE-2022-2874", "CVE-2022-2889", "CVE-2022-2923", "CVE-2022-2946", "CVE-2022-2980", "CVE-2022-2982", "CVE-2022-3016", "CVE-2022-3037", "CVE-2022-3099", "CVE-2022-3134", "CVE-2022-3153", "CVE-2022-3234", "CVE-2022-3235", "CVE-2022-3278", "CVE-2022-3296", "CVE-2022-3297", "CVE-2022-3324", "CVE-2022-3352", "CVE-2022-3705");
  script_tag(name:"creation_date", value:"2022-12-28 04:18:15 +0000 (Wed, 28 Dec 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-27 14:17:44 +0000 (Thu, 27 Jan 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4619-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4619-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224619-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201134");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204779");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-December/013343.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the SUSE-SU-2022:4619-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:

Updated to version 9.0.0814:

 * Fixing bsc#1192478 VUL-1: CVE-2021-3928: vim: vim is vulnerable to Stack-based Buffer Overflow
 * Fixing bsc#1203508 VUL-0: CVE-2022-3234: vim: Heap-based Buffer Overflow prior to 9.0.0483.
 * Fixing bsc#1203509 VUL-1: CVE-2022-3235: vim: Use After Free in GitHub prior to 9.0.0490.
 * Fixing bsc#1203820 VUL-0: CVE-2022-3324: vim: Stack-based Buffer Overflow in prior to 9.0.0598.
 * Fixing bsc#1204779 VUL-0: CVE-2022-3705: vim: use after free in function qf_update_buffer of the file quickfix.c
 * Fixing bsc#1203152 VUL-1: CVE-2022-2982: vim: use after free in qf_fill_buffer()
 * Fixing bsc#1203796 VUL-1: CVE-2022-3296: vim: stack out of bounds read in ex_finally() in ex_eval.c
 * Fixing bsc#1203797 VUL-1: CVE-2022-3297: vim: use-after-free in process_next_cpt_value() at insexpand.c
 * Fixing bsc#1203110 VUL-1: CVE-2022-3099: vim: Use After Free in ex_docmd.c
 * Fixing bsc#1203194 VUL-1: CVE-2022-3134: vim: use after free in do_tag()
 * Fixing bsc#1203272 VUL-1: CVE-2022-3153: vim: NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0404.
 * Fixing bsc#1203799 VUL-1: CVE-2022-3278: vim: NULL pointer dereference in eval_next_non_blank() in eval.c
 * Fixing bsc#1203924 VUL-1: CVE-2022-3352: vim: vim: use after free
 * Fixing bsc#1203155 VUL-1: CVE-2022-2980: vim: null pointer dereference in do_mouse()
 * Fixing bsc#1202962 VUL-1: CVE-2022-3037: vim: Use After Free in vim prior to 9.0.0321
 * Fixing bsc#1200884 Vim: Error on startup
 * Fixing bsc#1200902 VUL-0: CVE-2022-2183: vim: Out-of-bounds Read through get_lisp_indent() Mon 13:32
 * Fixing bsc#1200903 VUL-0: CVE-2022-2182: vim: Heap-based Buffer Overflow through parse_cmd_address() Tue 08:37
 * Fixing bsc#1200904 VUL-0: CVE-2022-2175: vim: Buffer Over-read through cmdline_insert_reg() Tue 08:37
 * Fixing bsc#1201249 VUL-0: CVE-2022-2304: vim: stack buffer overflow in spell_dump_compl()
 * Fixing bsc#1201356 VUL-1: CVE-2022-2343: vim: Heap-based Buffer Overflow in GitHub repository vim prior to 9.0.0044
 * Fixing bsc#1201359 VUL-1: CVE-2022-2344: vim: Another Heap-based Buffer Overflow vim prior to 9.0.0045
 * Fixing bsc#1201363 VUL-1: CVE-2022-2345: vim: Use After Free in GitHub repository vim prior to 9.0.0046.
 * Fixing bsc#1201620 vim: SLE-15-SP4-Full-x86_64-GM-Media1 and vim-plugin-tlib-1.27-bp154.2.18.noarch issue
 * Fixing bsc#1202414 VUL-1: CVE-2022-2819: vim: Heap-based Buffer Overflow in compile_lock_unlock()
 * Fixing bsc#1202552 VUL-1: CVE-2022-2874: vim: NULL Pointer Dereference in generate_loadvar()
 * Fixing bsc#1200270 VUL-1: CVE-2022-1968: vim: use after free in utf_ptr2char
 * Fixing bsc#1200697 VUL-1: CVE-2022-2124: vim: out of bounds read in current_quote()
 * Fixing bsc#1200698 VUL-1: CVE-2022-2125: vim: out of bounds read in get_lisp_indent()
 * Fixing bsc#1200700 VUL-1: CVE-2022-2126: vim: out of bounds ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'vim' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.0.0814~17.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.0.0814~17.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.0.0814~17.9.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.0.0814~17.9.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.0.0814~17.9.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.0.0814~17.9.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.0.0814~17.9.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.0.0814~17.9.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.0.0814~17.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.0.0814~17.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.0.0814~17.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.0.0814~17.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~9.0.0814~17.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.0.0814~17.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~9.0.0814~17.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~9.0.0814~17.9.1", rls:"SLES12.0SP5"))) {
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
