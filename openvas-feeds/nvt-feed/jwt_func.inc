# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# JSON Web Token (JWT) related functions
# - https://jwt.io/
# - https://jwt.io/introduction
# - https://datatracker.ietf.org/doc/html/rfc7519 (RFC 7519 - JSON Web Token (JWT))
# - https://datatracker.ietf.org/doc/html/rfc8725 (RFC 8725 - JSON Web Token Best Current Practices)
# - https://datatracker.ietf.org/doc/html/rfc7159 (RFC 7159 - The JavaScript Object Notation (JSON) Data Interchange Format) - For generic syntax on JSON

global_var JWT_TOKEN_HEADER;

# Currently supported signature algorithms
JWT_TOKEN_HEADER["ALG_NONE"] = "none";
JWT_TOKEN_HEADER["ALG_HS512"] = "HS512";

# @brief Creates a JSON Web Token (JWT) based on given header, payload and (optional) secret
#
# @param header  Array of parts from the header (at least the 'alg' part is mandatory, but 'type'
#                seems to be optional (e.g.
#                  make_array("alg", JWT_TOKEN_HEADER["ALG_NONE"])
#                or:
#                  make_array("alg", JWT_TOKEN_HEADER["ALG_NONE"], "typ", "JWT")
#                )
# @param payload Array of parts from the payload
#                (e.g. make_array("sub", "1234567890",
#                                 "name", "John Doe",
#                                 "admin", "true"))
#                If the value should not surrounded by '"' the string "###NOSTRING" can be added to
#                the value parameter.
#                (e.g. make_array("sub", "123456789###NOSTRING") which will result in
#                { "sub": 1234567890 } as some applications seem to need these
# @param secret  (Optional, depending on the algorithm used) base64 encoded secret to use to
#                create the signature
#
# @note This function doesn't add / use a '"typ":"JWT"' part in the header by default and this needs
#       to be added by the caller if required (see example arrays above).
#
# @todo (Or TBD):
#   - Some JWT related PoCs have only put apostrophes around strings and none around ints or
#     true/false (e.g. "foo": "test", vs. "bar": 123 or "foobar": true). Do we need to do that as well?
#
# @return The created JWT on success, NULL otherwise
#
function jwt_create_token(header, payload, secret) {
  local_var header, payload, secret;
  local_var alg, plain_header, part, plain_payload, enc_header, enc_payload, jwt_token;
  local_var split_value, signature, enc_signature;

  if (isnull(header)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#header#-#jwt_create_token");
    return;
  }

  if (!is_array(header)) {
    set_kb_item(name: "vt_debug_no_array/" + get_script_oid(), value: get_script_oid() + "#-#header#-#jwt_create_token");
    return;
  }

  alg = header["alg"];
  if (alg != JWT_TOKEN_HEADER["ALG_NONE"] && alg != JWT_TOKEN_HEADER["ALG_HS512"]) {
    set_kb_item(name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#alg '" + alg + "' not supported#-#jwt_create_token");
    return;
  }

  if (isnull(payload)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#payload#-#jwt_create_token");
    return;
  }

  if (!is_array(payload)) {
    set_kb_item(name: "vt_debug_no_array/" + get_script_oid(), value: get_script_oid() + "#-#payload#-#jwt_create_token");
    return;
  }

  # Header handling
  plain_header = "{";
  foreach part (keys(header)) {
    plain_header += '"' + part + '":"' + header[part] + '",';
  }
  plain_header = ereg_replace(pattern: ",$", string: plain_header, replace: "");
  plain_header += "}";

  # Payload handling
  plain_payload = "{";
  foreach part (keys(payload)) {
    split_value = split(payload[part], sep: "###", keep: FALSE);
    if (max_index(split_value) == 1) {
      plain_payload += '"' + part + '": "' + payload[part] + '", ';
    } else {
      if (split_value[1] == "NOSTRING") {
        plain_payload += '"' + part + '": ' + split_value[0] + ', ';
      } else {
        return;
      }
    }
  }
  plain_payload = ereg_replace(pattern: ", $", string: plain_payload, replace: "");
  plain_payload += "}";

  enc_header = base64(str: plain_header);
  enc_header = ereg_replace(pattern: "[=]*$", string: enc_header, replace: "");
  enc_payload = base64(str: plain_payload);
  enc_payload = ereg_replace(pattern: "[=]*$", string: enc_payload, replace: "");

  if (alg == JWT_TOKEN_HEADER["ALG_NONE"])
    jwt_token = enc_header + "." + enc_payload + ".AAA";
  else if (alg == JWT_TOKEN_HEADER["ALG_HS512"]) {
    if (!secret) {
      set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#secret#-#jwt_create_token");
      return;
    }

    # nb: Maybe we need in the future to take the secret not as a base64 encoded string. Then the below
    #     code would need to be changed.
    signature = HMAC_SHA512(data: enc_header + "." + enc_payload, key: base64_decode(str: secret));
    enc_signature = base64(str: signature);
    enc_signature = ereg_replace(pattern: "[=]*$", string: enc_signature, replace: "");
    enc_signature = str_replace(string: enc_signature, find: "/", replace: "_");
    enc_signature = str_replace(string: enc_signature, find: "+", replace: "-");

    jwt_token = enc_header + "." + enc_payload + "." + enc_signature;
  }

  return jwt_token;
}
