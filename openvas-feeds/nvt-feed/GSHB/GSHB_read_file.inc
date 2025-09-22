# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Function that reads the content of given file
#
# @param share  Windows IPC Share
# @param file   File path to read the content
# @param offset Position from which to start the file read
#
# @return The content of the file or FALSE if no connection to the remote
#         system could be opened or the file isn't readable.
#
function GSHB_read_file(share, file, offset) {

  local_var share, file, offset;
  local_var port, soc, name, r, prot, domain, login, pass, uid, tid, fid, size, content;

  port = kb_smb_transport();
  if(!port)
    port = 445;

  soc = open_sock_tcp(port);
  if(!soc)
    return FALSE;

  name = kb_smb_name();
  domain = kb_smb_domain();
  login = kb_smb_login();
  pass = kb_smb_password();

  if( ! get_kb_item( "login/SMB/kerberos/success" ) ) {
    info = smb_login_and_get_tid_uid(soc:soc, name:name, login:login, passwd:pass, domain:domain, share:share);
  } else {
    kdc = kb_smb_kdc();
    host = kb_smb_hostname();
    info = smb_login_and_get_tid_uid(soc:soc, name:name, login:login, passwd:pass, domain:domain, share:share, kdc:kdc, host:host );
  }

  if(isnull(info)) {
    close(soc);
    return FALSE;
  }

  uid = info["uid"];
  tid = info["tid"];

  fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
  if(!fid) {
    close(soc);
    return FALSE;
  }

  size = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);
  if(!size) {
    close(soc);
    return FALSE;
  }

  content = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:size, off:offset);
  return content;
}
